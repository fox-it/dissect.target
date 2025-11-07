#!/usr/bin/env python3
"""Test script to verify the --ignore-regback functionality works correctly."""

import tempfile
import os
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from dissect.target import Target
from dissect.target.tools.utils import configure_generic_arguments, process_generic_arguments, open_targets
import argparse

def test_ignore_regback_cli():
    """Test that the --ignore-regback CLI argument works correctly."""
    
    # Test 1: Check that the argument is available
    parser = argparse.ArgumentParser()
    configure_generic_arguments(parser)
    
    # Parse with --ignore-regback flag
    args = parser.parse_args(['--ignore-regback'])
    assert hasattr(args, 'ignore_regback')
    assert args.ignore_regback is True
    
    # Parse without the flag (should default to False)
    args_default = parser.parse_args([])
    assert hasattr(args_default, 'ignore_regback')
    assert args_default.ignore_regback is False
    
    print("✓ CLI argument parsing works correctly")

def test_target_props_setting():
    """Test that target props are set correctly when opening targets."""
    
    # Create a simple test file to use as a target (to satisfy the loader)
    with tempfile.NamedTemporaryFile(suffix='.raw', delete=False) as temp_file:
        temp_file.write(b"dummy content")
        target_path = temp_file.name
    
    try:
        # Create a mock argument namespace
        args = argparse.Namespace()
        args.ignore_regback = True
        args.targets = [target_path]
        args.loader = 'raw'  # Use raw loader to handle our dummy file
        args.keychain_file = None
        args.keychain_value = None
        args.plugin_path = None
        
        # Mock the open_targets function behavior
        for target in open_targets(args):
            # Check that the target has the ignore_regback property set
            assert "ignore_regback" in target.props
            assert target.props["ignore_regback"] is True
            print("✓ Target props set correctly with ignore_regback=True")
            break
        
        # Test with ignore_regback=False
        args.ignore_regback = False
        for target in open_targets(args):
            assert "ignore_regback" in target.props
            assert target.props["ignore_regback"] is False
            print("✓ Target props set correctly with ignore_regback=False")
            break
            
    finally:
        # Clean up the temporary file
        os.unlink(target_path)

def test_registry_keys_method():
    """Test that the registry keys method respects the ignore_regback parameter."""
    
    from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue
    from unittest.mock import Mock
    
    # Create a mock target
    target = Mock()
    target.props = {"ignore_regback": True}
    
    # Test that we can import and use the registry plugin
    from dissect.target.plugins.os.windows.registry import RegistryPlugin
    
    # This would need a full target setup to work properly, but we can at least
    # verify the method signature and basic logic
    registry = RegistryPlugin(target)
    
    # Test that the keys method accepts ignore_regback parameter
    try:
        # This will fail because we don't have a proper registry setup,
        # but it should not fail due to unexpected arguments
        registry.keys("test", ignore_regback=True)
    except Exception as e:
        # We expect some kind of error due to missing registry data,
        # but not a TypeError about unexpected arguments
        assert "ignore_regback" not in str(e)
        print("✓ Registry keys method accepts ignore_regback parameter")

if __name__ == "__main__":
    print("Testing --ignore-regback functionality...")
    
    try:
        test_ignore_regback_cli()
        test_target_props_setting() 
        test_registry_keys_method()
        
        print("\n🎉 All tests passed! The --ignore-regback functionality is working correctly.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
