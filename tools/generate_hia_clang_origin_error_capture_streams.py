"""Fixed capture streams with preserved actual failure phases."""
from tools.generate_hia_clang_origin_error_capture_common import write_module
from tools.generate_hia_clang_capture_streams import SOURCE
if __name__=='__main__':write_module('clang_origin_error_capture_streams',SOURCE,'decode')
