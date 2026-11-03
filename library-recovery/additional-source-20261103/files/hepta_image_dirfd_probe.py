"""Local independent POSIX probe for prospective Hepta NDU candidate image directory custody."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

class CohortContractError(ValueError):
    pass

def open_pinned_image_directory(image_dir):
    """Open every directory component with O_NOFOLLOW and retain its final descriptor."""
    if not image_dir:
        raise CohortContractError("candidate image bytes are required (--image-dir)")
    if not all((hasattr(os, "O_NOFOLLOW"), hasattr(os, "O_DIRECTORY"), os.open in os.supports_dir_fd)):
        raise CohortContractError("secure no-follow image directory descriptors unavailable")
    absolute = Path(os.path.abspath(os.fspath(image_dir)))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    fd = None
    try:
        fd = os.open(absolute.anchor, flags)
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise CohortContractError("image-dir is not a directory")
        return fd
    except (OSError, ValueError, TypeError) as exc:
        if fd is not None:
            os.close(fd)
        raise CohortContractError(f"image-dir must be a no-follow directory path: {exc}") from exc

@unittest.skipUnless(hasattr(os,"O_NOFOLLOW") and os.open in os.supports_dir_fd, "POSIX-only proof")
class TestPinnedImageDirectory(unittest.TestCase):
    def test_regular_dir_and_bounded_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            folder=Path(td)/'images'; folder.mkdir(); (folder/'a.jpg').write_bytes(b'original')
            fd=open_pinned_image_directory(folder)
            try:
                child_fd=os.open('a.jpg',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
                with os.fdopen(child_fd,'rb') as h:
                    self.assertEqual(h.read(),b'original')
            finally:os.close(fd)
    def test_parent_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); actual=root/'actual'; (actual/'images').mkdir(parents=True)
            (root/'alias').symlink_to(actual,target_is_directory=True)
            with self.assertRaisesRegex(CohortContractError,"no-follow"):
                open_pinned_image_directory(root/'alias'/'images')
    def test_final_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); actual=root/'actual'; actual.mkdir()
            (root/'alias').symlink_to(actual,target_is_directory=True)
            with self.assertRaises(CohortContractError):open_pinned_image_directory(root/'alias')
    def test_retained_directory_survives_rename_before_child_open(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); folder=root/'images'; folder.mkdir(); (folder/'a.jpg').write_bytes(b'original')
            fd=open_pinned_image_directory(folder)
            try:
                folder.rename(root/'renamed')
                folder.mkdir(); (folder/'a.jpg').write_bytes(b'forgery')
                with os.fdopen(os.open('a.jpg',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd),'rb') as h:
                    self.assertEqual(h.read(),b'original')
            finally:os.close(fd)
    def test_child_symlink_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); root.joinpath('images').mkdir(); root.joinpath('real').write_bytes(b'orig')
            root.joinpath('images','a.jpg').symlink_to(root/'real')
            fd=open_pinned_image_directory(root/'images')
            try:
                with self.assertRaises(OSError):os.open('a.jpg',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            finally:os.close(fd)

if __name__=='__main__':unittest.main(verbosity=2)
