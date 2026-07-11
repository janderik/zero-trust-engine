#!/usr/bin/env python3
"""Zero Trust Engine CLI - Command line interface for zero trust operations."""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.engine.core import ZeroTrustEngine, AccessRequest
from src.auth.identity import IdentityProvider
from src.auth.device import DeviceTrustManager
from src.policy.engine import PolicyEngine, PolicyContext


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Zero Trust Engine - Continuous verification security system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s start
  %(prog)s evaluate --user user123 --resource api/data --action read
  %(prog)s policies list
  %(prog)s devices list
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    start_parser = subparsers.add_parser("start", help="Start the zero trust engine")
    start_parser.add_argument("--config", help="Configuration file path")
    
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate an access request")
    eval_parser.add_argument("--user", required=True, help="User ID")
    eval_parser.add_argument("--device", default="device-default", help="Device ID")
    eval_parser.add_argument("--resource", required=True, help="Resource path")
    eval_parser.add_argument("--action", required=True, help="Action to perform")
    eval_parser.add_argument("--ip", default="127.0.0.1", help="Source IP address")
    
    policies_parser = subparsers.add_parser("policies", help="Manage policies")
    policies_parser.add_argument("action", choices=["list", "add", "remove"])
    policies_parser.add_argument("--name", help="Policy name")
    
    devices_parser = subparsers.add_parser("devices", help="Manage devices")
    devices_parser.add_argument("action", choices=["list", "check", "register"])
    devices_parser.add_argument("--device-id", help="Device ID")
    
    stats_parser = subparsers.add_parser("stats", help="Show engine statistics")
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()
    
    if not args.command:
        print("Zero Trust Engine v1.0.0")
        print("Use --help for usage information")
        sys.exit(0)
    
    engine = ZeroTrustEngine()
    engine.initialize()
    
    if args.command == "start":
        print("Zero Trust Engine started")
        print(f"Mode: {engine.config.get('engine', {}).get('mode', 'enforce')}")
        print("Engine is ready to evaluate access requests")
    
    elif args.command == "evaluate":
        request = AccessRequest(
            user_id=args.user,
            device_id=args.device,
            resource=args.resource,
            action=args.action,
            source_ip=args.ip
        )
        
        decision = engine.evaluate(request)
        
        print(f"\nAccess Request Evaluation")
        print(f"{'=' * 50}")
        print(f"User: {args.user}")
        print(f"Resource: {args.resource}")
        print(f"Action: {args.action}")
        print(f"{'=' * 50}")
        print(f"Verdict: {decision.verdict.value.upper()}")
        print(f"Allowed: {decision.allowed}")
        print(f"Reason: {decision.reason}")
        print(f"Risk Score: {decision.risk_score:.1f}")
    
    elif args.command == "policies":
        if args.action == "list":
            print("\nCurrent Policies")
            print("=" * 50)
            for policy in engine.policies:
                print(f"  {policy['name']}: {policy['effect']}")
    
    elif args.command == "devices":
        device_manager = DeviceTrustManager()
        
        if args.action == "list":
            print("\nRegistered Devices")
            print("=" * 50)
            devices = device_manager.get_all_devices()
            if not devices:
                print("  No devices registered")
            else:
                for device in devices:
                    print(f"  {device.device_id}: {device.hostname}")
        
        elif args.action == "register" and args.device_id:
            device = device_manager.register_device(args.device_id)
            print(f"Device registered: {device.device_id}")
    
    elif args.command == "stats":
        stats = engine.get_stats()
        print("\nEngine Statistics")
        print("=" * 50)
        print(f"Total Requests: {stats.get('total_requests', 0)}")
        print(f"Allowed: {stats.get('allowed', 0)}")
        print(f"Denied: {stats.get('denied', 0)}")
        print(f"Challenged: {stats.get('challenged', 0)}")
        print(f"Allow Rate: {stats.get('allow_rate', 0):.1f}%")


if __name__ == "__main__":
    main()
