"""Compatibility entry point for the maintained asset-list regression suite.

The previous file contained an incomplete test mixed with terminal transcript.
The merge installer preserves that original file in its source backup.
"""
import unittest
from asset_list_scope_regression import AssetListTests

if __name__ == "__main__":
    unittest.main(verbosity=2)
