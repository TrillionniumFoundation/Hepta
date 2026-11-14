# Static recovery scope

This recovery downloaded only GitHub artifact 14062024126 into a fresh /tmp/hia-runtime-artifact-recovery-20261114-dda7 directory. No former workspace, venv, /tmp or /dev/shm path was recreated. No restored executable, library, Python module, binder, CI workflow or product was executed.

The fixed ZIP length and SHA-256, all twelve ZIP member CRCs and contents, the eleven-entry ZIP manifest, the complete inner tar SHA-256/Git identity and gzip footer, and all 2,496 declared tar files were checked. Tar links, absolute paths, traversal, duplicate names and special files were refused. New output files have independent inode identity, original exported file modes and a separately captured new seven-stat map. A second reader fully read every restored file and checked bytes, SHA-256, Git blob identity, modes, new stats and the complete path set.

The retained exporter declares DEVELOPMENT_TOOL_DEPENDENCY_NOT_PRODUCT_QUALIFICATION. Its 6,487 omitted tool paths include site-packages, bytecode/cache files and .a files. Former venv configuration, installed packages, runtime mapping/inode identity, RPATH/loader behavior and dynamic execution qualification are not restored by this data-only operation. The suggested PYTHONHOME/LD_LIBRARY_PATH values in the original export were recorded but never applied to launch the restored interpreter.

This small custody package contains the manifests, new-file map, observations, exact data-only readers and exporter source. It intentionally excludes a duplicate copy of the ZIP, tar and 108 MB runtime payload. Those exact downloaded bytes remain in this new directory and are identified by fixed pins. No signed URL or credential is included. Complete custody of other missing Native/R5/VM evidence is not implied.
