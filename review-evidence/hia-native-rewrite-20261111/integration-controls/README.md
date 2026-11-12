# Source and supervisor integration observations

The first 39 controls use the exact source map in `controls.json`; later CI
supervisor changes are separate observations. The original two CI boundary
controls produced ten failing subcases, including accepted empty/incomplete
runs. After correction, eight actual outcome/CI boundary controls passed.
They do not stand in for running the unchanged native test modules.

The source-transfer control copied the exact ec484 Git commit and complete
3,121-file tree through an independent depth-one fetch. Every raw blob and file
mode matched; object files were single-link and there was no alternate object
store. This observes Git transfer only. The qualification runner still executes
all declared generators and compares the complete tree before and after them.

None of these observations is a cold receipt for the final integrated source,
a new native component pass, deployment or whole-product acceptance.
