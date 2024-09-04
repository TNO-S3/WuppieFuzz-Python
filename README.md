# WuppieFuzz

TNO developed WuppieFuzz, a coverage-guided REST API fuzzer developed on top of
LibAFL, targeting a wide audience of end-users, with a strong focus on
ease-of-use, explainability of the discovered flaws and modularity. WuppieFuzz
supports all three settings of testing (black box, grey box and white box).

## WuppieFuzz-Python

For Python there exists a quite extensive module to gather coverage information.
Specifically [coverage.py](https://coverage.readthedocs.io/). Out of the box
this module only writes coverage information to file once the Python process
terminates. As we work with never-ending services and wish to gather coverage
information whilst running the service, we needed to come up with a (smarter)
workaround.

### Usage

#### Setup

Install coverage.py, e.g.

```
python3.9 -m pip install coverage==7.2.7
```

Determine the location of your `site-packages` belonging to the specific python
executable that you are using to run the PUT: e.g.

```console
$ python3.9 -m site --user-site
/home/wupwup/.local/lib/python3.9/site-packages
```

Copy `sitecustomize.py` over to that same path

```console
$ cp sitecustomize.py <path to site-packages>
```

We recommend excluding files that aren't part of your PUT from coverage
collection. You can do that by specifying them in the `[run]` part of your
`.coveragerc` file as follows (note
[file patterns](https://coverage.readthedocs.io/en/7.0.0/source.html#file-patterns)
are supported):

```ini
[run]
omit =
    */sitecustomize.py
    /usr/lib/python*
    path/to/file.py
    unrelated_dir/*
```

More information on the omit configuration is found
[here](https://coverage.readthedocs.io/en/7.0.0/config.html#run-omit)

Copy (and modify) `.coveragerc` to the location where you are launching your
Python PUT.

#### Starting PUT

You can now launch the PUT as follows:

```
COVERAGE_PROCESS_START="<PATH TO .coveragerc>" python3.9 <Your regular python commands>
```

If you do not set the environment variable `COVERAGE_PROCESS_START`, coverage
collection will not start.

One can add `DEBUG_PYTHON_LCOV` environment variable to get extra logging,
`PORT_PYTHON_LCOV` to configure the port number (defaults to 3001).

#### Collect coverage in WuppieFuzz

Since this module makes coverage available in LCOV-format, use the
`--coverage-format lcov` flag, and specify `--coverage-host localhost:3001`, for
instance.

### Create coverage reports

After having run WuppieFuzz on the target coverage information can be obtained.
The coverage information is stored in the `.coverage`-file of the directory
where the target is run (possibly in a Docker container). The location of the
file can be customized by defining the environment variable `COVERAGE_FILE`. The
coverage data is written to the file on disconnect of a TCP-connection, which
automatically happens when WuppieFuzz has finished running.

The coverage file in combination with the source files of the application are
needed to create a coverage report. The coverage report can be generated as
follows (note that you need to be in the environment containing the
`.coverage`-file):

```bash
python -m coverage html --data-file=<PATH/TO/.coverage> --contexts=request_.* -d <OUTPUT_DIR> <SOURCE_FILES>
```

If there are lots of source files, you may want to use an inline
`$(find . -name "*.py)"` to include them all.

The resulting report in `OUTPUT_DIR` shows the coverage obtained during the
entire fuzzing run. If you want to coverage information of the initialization
you have to change a flag: `--contexts=initial_coverage`. The report directory
does not depend on any other files, you can copy it anywhere and view the report
in a browser by opening `index.html`.

#### Disclaimer 1/2

- The init command, which signals to the TCP server that the initialization of
  the target has been finished.
- The text-dump command, which signals to the TCP server to dump the coverage in
  text format.
- The html-dump command, which signals to the TCP server to dump the coverage in
  html format.

A command is always preprended with the following byte-sequence:
`0xDE, 0xAD, 0xC0, 0xDE`. After the byte sequence a string of four characters in
UTF-8 is expected must be one of: `["init", "text", "html"]`. Finally a single
byte representing which coverage should be dumped.

- 0 to dump all information
- 1 to dump only the initial coverage information
- 2 to dump the coverage obtained after initialization

#### Disclaimer 2/2

All python processes using the site-packages as listed above _will_ run the
`sitecustomize.py` before starting. Side-effects are prevented, nothing happens
when `COVERAGE_PROCESS_START` is not set.
