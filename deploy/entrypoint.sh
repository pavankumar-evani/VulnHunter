#!/bin/sh
# Container entrypoint: prepare the database, make sure there is a first admin, then start Quanta.
set -e
# An explicit command runs as given (for example `docker run IMAGE python cli/quanta_admin.py gen-key`): the image must not start the whole
# web application when someone only wants a one-off tool.
if [ "$#" -gt 0 ]; then
  exec "$@"
fi
python cli/quanta_admin.py init
# a production deployment starts empty: set the bundled sample data aside (no-op once real data exists)
if [ "$QUANTA_PRODUCTION" = "true" ] && [ "$QUANTA_KEEP_SAMPLE_DATA" != "true" ]; then python cli/quanta_admin.py clear-sample-data --yes; fi
python cli/quanta_admin.py bootstrap
python cli/quanta_admin.py check || echo "Configuration check reported failures above; fix them before real use."
exec python dashboard/app.py
