# This file is required to make Python treat the directory as a package.
# It can be left empty, or you can put package initialization code here.

# Optionally, you can import test modules here to make them easier to run:

# If you have multiple test files, you can import them all here:
# from .test_client import TestClient
# from .test_utils import TestUtils
# Comment out or remove this line:
# from .test_server import TestServer

# You can also define package-level variables or functions if needed:
TEST_CONFIG_PATH = 'path/to/test/config.ini'

def run_all_tests():
    import unittest
    unittest.main(verbosity=2)

# This allows you to run all tests by executing this file
if __name__ == '__main__':
    run_all_tests()