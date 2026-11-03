# Frozen pre-extraction oracle inputs

Exact unmodified production source bytes from #622 / a0a8fe8f870a892172e7b35104bd93fb3c4e6377.
These are historical test data, not imported as production modules or a second
maintained loader. candidate.py retains the original SHA-256 drift checks and
applies the existing isolated recipe to these files. Future production edits must
not overwrite these baseline bytes to make a differential failure disappear.
