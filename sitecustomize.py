import collections
import datetime
import os
import traceback
from multiprocessing.pool import ThreadPool
from typing import Any

if os.environ.get("COVERAGE_PROCESS_START"):
    print("WuppieFuzz - Python LCOV code coverage monitor is booting..")
    try:
        import sys

        import coverage
        from coverage.exceptions import NoDataError, NotPython
        from coverage.files import GlobMatcher, prep_patterns
        from coverage.lcovreport import LcovReporter
        from coverage.plugin import FileReporter
        from coverage.results import Analysis, Numbers

    except Exception as excep:
        print("WuppieFuzz - Could not import coverage package properly, exiting.")
        print("Raised exception:", excep)
        from sys import exit

        exit(1)

    def numbits_to_nums(numbits: bytes):
        return [
            byte_i * 8 + bit_i
            for byte_i, byte in enumerate(numbits)
            for bit_i in range(8)
            if (byte & (1 << bit_i))
        ]

    #### BLOCK -- Caching to increase performance
    class CachedAnalysis(Analysis):
        def __init__(self, *args, **kwargs) -> None:
            self.cache = {}
            super().__init__(*args, **kwargs)

        def update_analysis(self, data, line_data, arc_data):
            """
            Extension to update analysis data without additional db queries
            """
            self.cache = {}
            self.data = data
            self.arc_data = arc_data
            # Identify missing statements.
            executed = list(line_data.get(self.data._file_id(self.filename), []))
            executed = self.file_reporter.translate_lines(executed)
            self.executed = executed
            self.missing = self.statements - self.executed

            if self.data.has_arcs():
                self._arc_possibilities = sorted(self.file_reporter.arcs())
                self.exit_counts = self.file_reporter.exit_counts()
                self.no_branch = self.file_reporter.no_branch_lines()
                n_branches = self._total_branches()
                mba = self.missing_branch_arcs()
                n_partial_branches = sum(
                    len(v) for k, v in mba.items() if k not in self.missing
                )
                n_missing_branches = sum(len(v) for k, v in mba.items())
            else:
                self._arc_possibilities = []
                self.exit_counts = {}
                self.no_branch = set()
                n_branches = n_partial_branches = n_missing_branches = 0

            self.numbers = Numbers(
                # precision=precision,
                n_files=1,
                n_statements=len(self.statements),
                n_excluded=len(self.excluded),
                n_missing=len(self.missing),
                n_branches=n_branches,
                n_partial_branches=n_partial_branches,
                n_missing_branches=n_missing_branches,
            )

        def arcs_executed(self):
            """Returns a sorted list of the arcs actually executed in the code."""
            executed = self.cache.get("executed", ())
            if not executed:
                executed = list(
                    self.arc_data.get(self.data._file_id(self.filename), [])
                )
                executed = sorted(self.file_reporter.translate_arcs(executed))
                self.cache["executed"] = executed
            return executed

        def arcs_missing(self):
            """Returns a sorted list of the un-executed arcs in the code."""
            missing = self.cache.get("missing", ())
            if not missing:
                possible = self.arc_possibilities()
                executed = self.arcs_executed()
                missing = sorted(
                    p
                    for p in possible
                    if p not in executed
                    and p[0] not in self.no_branch
                    and p[1] not in self.excluded
                )
                self.cache["missing"] = missing
            return missing

        def missing_branch_arcs(self):
            """Return arcs that weren't executed from branch lines.
            Returns {l1:[l2a,l2b,...], ...}
            """
            mba = self.cache.get("mba", collections.defaultdict(list))
            if not mba:
                missing = self.arcs_missing()
                branch_lines = set(self._branch_lines())
                for l1, l2 in missing:
                    if l1 in branch_lines:
                        mba[l1].append(l2)
                self.cache["mba"] = mba
            return mba

        def executed_branch_arcs(self):
            """Return arcs that were executed from branch lines.
            Returns {l1:[l2a,l2b,...], ...}
            """
            eba = self.cache.get("eba", collections.defaultdict(list))
            if not eba:
                executed = self.arcs_executed()
                branch_lines = set(self._branch_lines())
                for l1, l2 in executed:
                    if l1 in branch_lines:
                        eba[l1].append(l2)
                self.cache["eba"] = eba
            return eba

        def branch_stats(self, missing_arcs=None):
            """Get stats about branches.
            Returns a dict mapping line numbers to a tuple:
            (total_exits, taken_exits).
            """
            stats = self.cache.get("branch_stats", {})
            if not stats:
                if missing_arcs is None:
                    missing_arcs = self.missing_branch_arcs()
                for lnum in self._branch_lines():
                    exits = self.exit_counts[lnum]
                    missing = len(missing_arcs[lnum])
                    stats[lnum] = (exits, exits - missing)
                self.cache["branch_stats"] = stats
            return stats

    def _analyze(self, it):
        """Analyze a single morf or code unit.
        Returns an `CachedAnalysis` object.
        """
        # All reporting comes through here, so do reporting initialization.
        self._init()
        self._post_init()

        data = self.get_data()
        if not isinstance(it, FileReporter):
            it = self._get_file_reporter(it)

        return CachedAnalysis(data, self.config.precision, it, self._file_mapper)

    coverage.Coverage._analyze = _analyze

    caching = {}
    file_reporters = None

    def get_analysis_to_report(coverage, morfs, regather_data=True):
        """
        Patched version using caching and a single query to get all covered lines of all files
        """
        global file_reporters
        if file_reporters is None:
            file_reporters = coverage._get_file_reporters(morfs)
        config = coverage.config

        if config.report_include:
            matcher = GlobMatcher(
                prep_patterns(config.report_include), "report_include"
            )
            file_reporters = [fr for fr in file_reporters if matcher.match(fr.filename)]

        if config.report_omit:
            matcher = GlobMatcher(prep_patterns(config.report_omit), "report_omit")
            file_reporters = [
                fr for fr in file_reporters if not matcher.match(fr.filename)
            ]

        if not file_reporters:
            raise NoDataError("No data to report.")
        if regather_data:
            data = coverage.get_data()
            with data._connect() as con:
                # Get files data.
                with con.execute("select file_id, numbits from line_bits") as cur:
                    line_data = {}
                    for file_id, numbits in cur:
                        cur_val = line_data.setdefault(file_id, set())
                        cur_val.update(numbits_to_nums(numbits))
                with con.execute(
                    "select distinct file_id, fromno, tono from arc"
                ) as cur:
                    arc_data = {
                        file_id: [fromno, tono] for (file_id, fromno, tono) in cur
                    }

        file_reporters = sorted(file_reporters)

        for fr in file_reporters:
            try:
                if str(fr) in caching:
                    analysis = caching[str(fr)]
                else:
                    analysis = coverage._analyze(fr)
                    caching[str(fr)] = analysis
                if regather_data:
                    analysis.update_analysis(
                        data=data, line_data=line_data, arc_data=arc_data
                    )
            except NotPython:
                # Only report errors for .py files, and only if we didn't
                # explicitly suppress those errors.
                # NotPython is only raised by PythonFileReporter, which has a
                # should_be_python() method.
                if fr.should_be_python():
                    if config.ignore_errors:
                        msg = f"Couldn't parse Python file '{fr.filename}'"
                        coverage._warn(msg, slug="couldnt-parse")
                    else:
                        raise
            except Exception as exc:
                if config.ignore_errors:
                    msg = f"Couldn't parse '{fr.filename}': {exc}".rstrip()
                    coverage._warn(msg, slug="couldnt-parse")
                else:
                    raise
            else:
                yield (fr, analysis)

    def report_lcov(self, morfs, outfile):
        """
        Renders the full lcov report.
        outfile is the file object to write the file into.
        """
        self.coverage.get_data()
        outfile = outfile or sys.stdout
        for fr, analysis in get_analysis_to_report(self.coverage, morfs):
            self.get_lcov(fr, analysis, outfile)

        return self.total.n_statements and self.total.pc_covered

    def get_lcov(self, fr, analysis, outfile=None):
        """Produces the lcov data for a single file.
        This currently supports both line and branch coverage,
        however function coverage is not supported.
        """
        self.total += analysis.numbers

        outfile.write(b"TN:\n")
        outfile.write(b"SF:%b\n" % fr.relative_filename().encode())
        # source_lines = fr.source().splitlines()

        for covered in analysis.executed:
            # Note: Coverage.py currently only supports checking *if* a line
            # has been executed, not how many times, so we set this to 1 for
            # nice output even if it's technically incorrect.

            # The lines below calculate a 64-bit encoded md5 hash of the line
            # corresponding to the DA lines in the lcov file, for either case
            # of the line being covered or missed in coverage.py. The final two
            # characters of the encoding ("==") are removed from the hash to
            # allow genhtml to run on the resulting lcov file.
            # if source_lines:
            #     if covered-1 >= len(source_lines):
            #         break
            #     line = source_lines[covered-1]
            # else:
            #     line = ""
            # outfile.write(f"DA:{covered},1,{line_hash(line)}\n")
            outfile.write(b"DA:%d,1,-\n" % covered)

        for missed in analysis.missing:
            # assert source_lines
            # line = source_lines[missed-1]
            # hashed = base64.b64encode(md5(line).digest()).decode().rstrip("=")
            # outfile.write(f"DA:{missed},0,{line_hash(line)}\n")
            outfile.write(b"DA:%d,0,-\n" % missed)

        outfile.write(b"LF:%d\n" % analysis.numbers.n_statements)
        outfile.write(b"LH:%d\n" % analysis.numbers.n_executed)

        # More information dense branch coverage data.
        missing_arcs = analysis.missing_branch_arcs()
        executed_arcs = analysis.executed_branch_arcs()
        for block_number, block_line_number in enumerate(
            analysis.branch_stats().keys()
        ):
            for branch_number, line_number in enumerate(
                missing_arcs[block_line_number]
            ):
                # The exit branches have a negative line number,
                # this will not produce valid lcov. Setting
                # the line number of the exit branch to 0 will allow
                # for valid lcov, while preserving the data.
                line_number = max(line_number, 0)
                outfile.write(
                    b"BRDA:%d,%d,%d,-\n" % line_number,
                    block_number,
                    branch_number,
                )

            # The start value below allows for the block number to be
            # preserved between these two for loops (stopping the loop from
            # resetting the value of the block number to 0).
            for branch_number, line_number in enumerate(
                executed_arcs[block_line_number],
                start=len(missing_arcs[block_line_number]),
            ):
                line_number = max(line_number, 0)
                outfile.write(
                    b"BRDA:%d,%d,%d,1\n" % line_number,
                    block_number,
                    branch_number,
                )

        # Summary of the branch coverage.
        if analysis.has_arcs():
            branch_stats = analysis.branch_stats()
            brf = sum(t for t, k in branch_stats.values())
            brh = brf - sum(t - k for t, k in branch_stats.values())
            outfile.write(b"BRF:%d\n" % brf)
            outfile.write(b"BRH:%d\n" % brh)

        outfile.write(b"end_of_record\n")

    LcovReporter.report = report_lcov
    LcovReporter.get_lcov = get_lcov
    ### ENDBLOCK --

    cov = coverage.process_startup()
    initial_coverage_context = "initial_coverage"
    cov.switch_context(initial_coverage_context)

    import socket
    import threading
    from io import BytesIO

    DEBUG = False
    if os.environ.get("DEBUG_PYTHON_LCOV"):
        DEBUG = True
        print("Enabled debug information")

    PORT = os.environ.get("PORT_PYTHON_LCOV", 3001)

    def create_dynamic_context_string(
        request_nb: int,
    ):
        timestamp = datetime.datetime.utcnow().isoformat()
        return f"request_{request_nb}_{timestamp}"

    class LCOVSocket(socket.socket):
        lcov_reporter = LcovReporter(cov)
        reset_request_number = 0
        HEADER_SIZE = 8
        REQUEST_HEADER = bytearray([0x01, 0xC0, 0xC0, 0x10, 0x07])
        BLOCK_CMD_DUMP = 0x40
        COVERAGE_INFO_RESPONSE = bytearray([0x11])
        CMD_OK_RESPONSE = bytearray([0x20])
        latest_context_name = initial_coverage_context

        pool = ThreadPool(processes=2)
        total_coverage_mutext = threading.Lock()
        morfs = set()

        @staticmethod
        def receive(nb_bytes, conn):
            # Ensure that exactly the desired amount of bytes is received
            received = bytearray()
            while len(received) < nb_bytes:
                new_bytes = conn.recv(nb_bytes - len(received))
                if not new_bytes:
                    print("WuppieFuzz - TCP Client disconnected while receiving bytes")
                    raise BrokenPipeError("Client probably disconnected")
                received += new_bytes
            return received

        def get_lcov(self) -> bytes:
            """
            Return the coverage information of the latest context in bytes
            """
            # cache the morfs to increase performance
            if len(self.morfs) == 0:
                self.morfs = cov.get_data().measured_files()
                if DEBUG:
                    print(f"WuppieFuzz - Coverage measure for files {self.morfs}")

            outfile = BytesIO()
            # take only the latests context into consideration
            cov._data.set_query_contexts([self.latest_context_name])

            lcov_reporter = LcovReporter(cov)
            lcov_reporter.report(morfs=None, outfile=outfile)

            # allow all types of context again
            cov._data.set_query_contexts(None)

            return outfile.getvalue()

        def reset_cov(self):
            """
            To reset the data we change the coverage context. Changing the context takes
            less time than erasing all the data and is usefull for benchmarkign/debugging
            """
            new_context_name = create_dynamic_context_string(self.reset_request_number)
            cov.switch_context(new_context_name)

            self.latest_context_name = new_context_name
            self.reset_request_number += 1

            if DEBUG:
                print(f"WuppieFuzz - Coverage context changed to: {new_context_name}")

        def send(self, connection: socket.socket, *args: Any, **kwargs: Any):
            try:
                connection.send(*args, **kwargs)
            except Exception as excep:
                print("WuppieFuzz - TCP Client disconnected while sending bytes")
                raise excep

        def start(self) -> None:
            try:
                self.start_listening()
            except Exception as excep:
                traceback.print_exc(excep)

        def start_listening(self) -> None:
            print(f"Wuppiefuzz - Started listening", flush=True)
            connection, address = self.accept()
            print(f"WuppieFuzz - Incoming TCP connection from {address}", flush=True)
            try:
                while True:
                    header = self.receive(self.HEADER_SIZE, connection)
                    assert (
                        header[0:5] == self.REQUEST_HEADER
                    ), f"Received incorrect header (got {header[0:5]}, expected {self.REQUEST_HEADER}) in request"
                    cmd = header[5]
                    if cmd == self.BLOCK_CMD_DUMP:
                        lcov = self.get_lcov()
                        size = len(lcov).to_bytes(4, "little", signed=False)
                        self.send(connection, self.COVERAGE_INFO_RESPONSE)
                        self.send(connection, size)
                        self.send(connection, lcov)
                        if DEBUG:
                            print(
                                f"WuppieFuzz - Sent {int.from_bytes(size, 'little', signed=False)} bytes in LCOV info"
                            )

                    reset_byte = header[7]
                    if reset_byte:
                        self.reset_cov()

                    self.send(connection, self.CMD_OK_RESPONSE)
            except Exception as e:
                print(f"Received exception {e}")
            finally:
                print("WuppieFuzz - TCP connection lost, waiting for reconnect")
                if DEBUG:
                    print(
                        f"WuppieFuzz - Saving coverage information of {len(cov._data.measured_files())} files"
                    )
                cov.save()
                self.start_listening()

    lcov_sock = LCOVSocket(socket.AF_INET, socket.SOCK_STREAM)
    lcov_sock.bind(("0.0.0.0", PORT))
    lcov_sock.listen(1)
    thread = threading.Thread(target=lcov_sock.start)
    thread.daemon = True
    thread.start()

    print(
        f"WuppieFuzz - Started LCOV code coverage monitor TCP server in background (port {PORT})"
    )
