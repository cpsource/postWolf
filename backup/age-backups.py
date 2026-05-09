#!/usr/bin/env python3
"""
Backup retention management tool for Neon database backups.

Implements a tiered retention policy:
- Daily backups: Keep most recent N days (one backup per day)
- Weekly backups: Keep most recent N weeks (one backup per ISO week)
- Monthly backups: Keep most recent N months (one backup per month)

Usage:
    python3 age-backups.py --keep-daily-backups 7 --keep-weekly-backups 4 --keep-monthly-backups 6
    python3 age-backups.py --keep-daily-backups 7 --dry-run
    python3 age-backups.py --keep-weekly-backups 4 --local
    python3 age-backups.py --keep-monthly-backups 12 --remote
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

VERSION = "0.1.0"

# Default paths
SCRIPT_DIR = Path(__file__).parent.resolve()
LOCAL_BACKUP_DIR = SCRIPT_DIR / "db"
S3_BUCKET = "s3://postwolf-neon-backups"

# Backup filename pattern: postwolf_backup_YYYYMMDD_HHMMSS.sql
BACKUP_PATTERN = re.compile(r'^postwolf_backup_(\d{8})_(\d{6})\.sql$')


def parse_backup_filename(filename):
    """
    Parse backup filename and return datetime object.
    Returns None if filename doesn't match expected pattern.
    """
    match = BACKUP_PATTERN.match(filename)
    if not match:
        return None

    date_str = match.group(1)  # YYYYMMDD
    time_str = match.group(2)  # HHMMSS

    try:
        dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
        return dt
    except ValueError:
        return None


def get_local_backups():
    """Get list of backup files from local directory."""
    backups = []

    if not LOCAL_BACKUP_DIR.exists():
        print(f"Warning: Local backup directory does not exist: {LOCAL_BACKUP_DIR}")
        return backups

    for f in LOCAL_BACKUP_DIR.iterdir():
        if f.is_file() and f.name.endswith('.sql'):
            dt = parse_backup_filename(f.name)
            if dt:
                backups.append({
                    'filename': f.name,
                    'path': str(f),
                    'datetime': dt,
                    'source': 'local'
                })

    return sorted(backups, key=lambda x: x['datetime'], reverse=True)


def get_remote_backups():
    """Get list of backup files from S3."""
    backups = []

    try:
        result = subprocess.run(
            ['aws', 's3', 'ls', S3_BUCKET + '/'],
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error listing S3 bucket: {e.stderr}")
        return backups
    except FileNotFoundError:
        print("Error: AWS CLI not found. Install with 'pip install awscli'")
        return backups

    # Parse S3 ls output: "2026-05-09 22:30:00  12345678 postwolf_backup_20260509_223000.sql"
    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 4:
            filename = parts[-1]
            dt = parse_backup_filename(filename)
            if dt:
                backups.append({
                    'filename': filename,
                    'path': f"{S3_BUCKET}/{filename}",
                    'datetime': dt,
                    'source': 'remote'
                })

    return sorted(backups, key=lambda x: x['datetime'], reverse=True)


def get_day_key(dt):
    """Get day key (YYYY-MM-DD) for a datetime."""
    return dt.strftime('%Y-%m-%d')


def get_week_key(dt):
    """
    Get ISO week key (YYYY-WNN) for a datetime.
    Uses ISO week numbering (1-52/53).
    Handles year rollover correctly.
    """
    iso_year, iso_week, _ = dt.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"


def get_month_key(dt):
    """Get month key (YYYY-MM) for a datetime."""
    return dt.strftime('%Y-%m')


def select_backups_to_keep(backups, keep_daily, keep_weekly, keep_monthly, reference_date=None):
    """
    Select which backups to keep based on retention policy.

    Args:
        backups: list of backup dicts
        keep_daily: number of daily backups to keep
        keep_weekly: number of weekly backups to keep
        keep_monthly: number of monthly backups to keep
        reference_date: optional datetime - exclude backups newer than this date (for testing)

    Returns:
        keep_set: set of filenames to keep
        keep_reasons: dict mapping filename to set of reasons ('daily', 'weekly', 'monthly')

    Note:
        - Daily: includes current day
        - Weekly: excludes current week (weekly backups are for prior weeks)
        - Monthly: excludes current month (monthly backups are for prior months)
    """
    keep_set = set()
    keep_reasons = defaultdict(set)

    # Determine "today" for calculating current week/month
    today = reference_date if reference_date else datetime.now()
    current_week = get_week_key(today)
    current_month = get_month_key(today)

    # Filter backups to only those on or before reference_date (if provided)
    if reference_date:
        # Include backups from the reference date and earlier
        filtered_backups = [b for b in backups if b['datetime'].date() <= reference_date.date()]
    else:
        filtered_backups = backups

    # Group backups by day, week, month
    by_day = defaultdict(list)
    by_week = defaultdict(list)
    by_month = defaultdict(list)

    for backup in filtered_backups:
        dt = backup['datetime']
        filename = backup['filename']

        by_day[get_day_key(dt)].append(backup)
        by_week[get_week_key(dt)].append(backup)
        by_month[get_month_key(dt)].append(backup)

    # Keep N most recent periods that have backups

    # Daily: keep most recent backup from each of the N most recent days (includes today)
    if keep_daily > 0:
        days = sorted(by_day.keys(), reverse=True)[:keep_daily]
        for day in days:
            most_recent = max(by_day[day], key=lambda x: x['datetime'])
            keep_set.add(most_recent['filename'])
            keep_reasons[most_recent['filename']].add('daily')

    # Weekly: keep most recent backup from each of the N most recent ISO weeks (excludes current week)
    if keep_weekly > 0:
        weeks = sorted([w for w in by_week.keys() if w != current_week], reverse=True)[:keep_weekly]
        for week in weeks:
            most_recent = max(by_week[week], key=lambda x: x['datetime'])
            keep_set.add(most_recent['filename'])
            keep_reasons[most_recent['filename']].add('weekly')

    # Monthly: keep most recent backup from each of the N most recent months (excludes current month)
    if keep_monthly > 0:
        months = sorted([m for m in by_month.keys() if m != current_month], reverse=True)[:keep_monthly]
        for month in months:
            most_recent = max(by_month[month], key=lambda x: x['datetime'])
            keep_set.add(most_recent['filename'])
            keep_reasons[most_recent['filename']].add('monthly')

    return keep_set, keep_reasons


def delete_local_backup(backup, dry_run=False):
    """Delete a local backup file."""
    path = Path(backup['path'])
    if dry_run:
        print(f"  [DRY RUN] Would delete local: {backup['filename']}")
        return True

    try:
        path.unlink()
        print(f"  Deleted local: {backup['filename']}")
        return True
    except Exception as e:
        print(f"  Error deleting {backup['filename']}: {e}")
        return False


def delete_remote_backup(backup, dry_run=False):
    """Delete a backup from S3."""
    if dry_run:
        print(f"  [DRY RUN] Would delete remote: {backup['filename']}")
        return True

    try:
        subprocess.run(
            ['aws', 's3', 'rm', backup['path']],
            capture_output=True,
            check=True
        )
        print(f"  Deleted remote: {backup['filename']}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  Error deleting {backup['filename']}: {e.stderr}")
        return False


def print_backup_summary(backups, title):
    """Print a summary of backups grouped by retention period."""
    if not backups:
        print(f"\n{title}: No backups found")
        return

    print(f"\n{title}: {len(backups)} backup(s)")
    print("-" * 60)

    for backup in backups[:10]:  # Show first 10
        dt = backup['datetime']
        week_key = get_week_key(dt)
        print(f"  {backup['filename']}  [{get_day_key(dt)}] [Week {week_key}]")

    if len(backups) > 10:
        print(f"  ... and {len(backups) - 10} more")


def print_backup_directory(backups, keep_reasons, title):
    """
    Print a directory listing showing date, backup type, and filename.

    Format:
    DATE        ISO-WEEK  TYPE              FILENAME
    2026-05-09  W19       daily,weekly      postwolf_backup_20260509_223000.sql
    """
    if not backups:
        print(f"\n{title}: No backups found")
        return

    print(f"\n{title}")
    print("=" * 90)
    print(f"{'DATE':<12} {'ISO-WEEK':<10} {'TYPE':<18} {'FILENAME'}")
    print("-" * 90)

    for backup in backups:
        dt = backup['datetime']
        filename = backup['filename']
        date_str = get_day_key(dt)
        week_str = get_week_key(dt)

        # Get retention type(s) for this backup
        if filename in keep_reasons:
            types = keep_reasons[filename]
            type_str = ','.join(sorted(types))
        else:
            type_str = '-delete-'

        print(f"{date_str:<12} {week_str:<10} {type_str:<18} {filename}")

    print("-" * 90)


def main():
    parser = argparse.ArgumentParser(
        description='Manage backup retention with daily/weekly/monthly policies',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --keep-daily-backups 7 --keep-weekly-backups 4 --keep-monthly-backups 6
  %(prog)s --keep-daily-backups 7 --dry-run
  %(prog)s --keep-weekly-backups 4 --local
  %(prog)s --keep-monthly-backups 12 --remote
  %(prog)s --keep-daily-backups 7 --list --dry-run
  %(prog)s --keep-monthly-backups 2 --todays-date 2026-02-15 --dry-run --list

Notes:
  - Uses ISO week numbering (weeks 1-52/53)
  - Week 1 is the week containing the first Thursday of the year
  - Handles year/month rollover correctly
  - At least one --keep-*-backups option must be specified
        """
    )

    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    parser.add_argument('--keep-daily-backups', type=int, default=0, metavar='N',
                        help='Keep N most recent daily backups (one per day)')
    parser.add_argument('--keep-weekly-backups', type=int, default=0, metavar='N',
                        help='Keep N most recent weekly backups (one per ISO week)')
    parser.add_argument('--keep-monthly-backups', type=int, default=0, metavar='N',
                        help='Keep N most recent monthly backups (one per month)')

    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be deleted without actually deleting')
    parser.add_argument('--local', action='store_true',
                        help='Work only on local files')
    parser.add_argument('--remote', action='store_true',
                        help='Work only on remote files (S3)')

    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Show detailed information')
    parser.add_argument('--list', action='store_true',
                        help='Show directory listing with date, backup type, and filename')
    parser.add_argument('--todays-date', metavar='YYYY-MM-DD',
                        help='Simulate running on this date (for testing retention policy)')

    args = parser.parse_args()

    # Parse --todays-date if provided
    reference_date = None
    if args.todays_date:
        try:
            reference_date = datetime.strptime(args.todays_date, '%Y-%m-%d')
        except ValueError:
            parser.error(f"Invalid date format: {args.todays_date}. Use YYYY-MM-DD.")

    # Validate arguments
    if args.keep_daily_backups == 0 and args.keep_weekly_backups == 0 and args.keep_monthly_backups == 0:
        parser.error("At least one of --keep-daily-backups, --keep-weekly-backups, or --keep-monthly-backups must be specified")

    if args.keep_daily_backups < 0 or args.keep_weekly_backups < 0 or args.keep_monthly_backups < 0:
        parser.error("Retention counts must be non-negative")

    # If neither --local nor --remote specified, do both
    do_local = args.local or (not args.local and not args.remote)
    do_remote = args.remote or (not args.local and not args.remote)

    print("=" * 60)
    print("Backup Retention Management")
    print("=" * 60)
    print(f"Version: {VERSION}")
    if reference_date:
        print(f"Simulated date: {reference_date.strftime('%Y-%m-%d')} ({get_week_key(reference_date)})")
    print(f"Retention policy:")
    if args.keep_daily_backups > 0:
        print(f"  Daily:   Keep {args.keep_daily_backups} most recent day(s)")
    if args.keep_weekly_backups > 0:
        print(f"  Weekly:  Keep {args.keep_weekly_backups} most recent ISO week(s)")
    if args.keep_monthly_backups > 0:
        print(f"  Monthly: Keep {args.keep_monthly_backups} most recent month(s)")
    print(f"Scope: {'local' if args.local else 'remote' if args.remote else 'local + remote'}")
    if args.dry_run:
        print("Mode: DRY RUN (no deletions)")

    total_deleted = 0
    total_kept = 0

    # Process local backups
    if do_local:
        print(f"\n{'='*60}")
        print("LOCAL BACKUPS")
        print(f"Directory: {LOCAL_BACKUP_DIR}")
        print("=" * 60)

        local_backups = get_local_backups()

        if args.verbose:
            print_backup_summary(local_backups, "Found")

        if local_backups:
            keep_set, keep_reasons = select_backups_to_keep(
                local_backups,
                args.keep_daily_backups,
                args.keep_weekly_backups,
                args.keep_monthly_backups,
                reference_date
            )

            to_keep = [b for b in local_backups if b['filename'] in keep_set]
            to_delete = [b for b in local_backups if b['filename'] not in keep_set]

            # Show directory listing if requested
            if args.list:
                print_backup_directory(local_backups, keep_reasons, "Local Backup Directory")

            print(f"\nKeeping: {len(to_keep)} backup(s)")
            for backup in to_keep:
                dt = backup['datetime']
                types = ','.join(sorted(keep_reasons.get(backup['filename'], set())))
                print(f"  KEEP: {backup['filename']} [{get_day_key(dt)}] [Week {get_week_key(dt)}] ({types})")

            if to_delete:
                print(f"\nDeleting: {len(to_delete)} backup(s)")
                for backup in to_delete:
                    delete_local_backup(backup, args.dry_run)
                    total_deleted += 1
            else:
                print("\nNo backups to delete.")

            total_kept += len(to_keep)
        else:
            print("No local backups found.")

    # Process remote backups
    if do_remote:
        print(f"\n{'='*60}")
        print("REMOTE BACKUPS (S3)")
        print(f"Bucket: {S3_BUCKET}")
        print("=" * 60)

        remote_backups = get_remote_backups()

        if args.verbose:
            print_backup_summary(remote_backups, "Found")

        if remote_backups:
            keep_set, keep_reasons = select_backups_to_keep(
                remote_backups,
                args.keep_daily_backups,
                args.keep_weekly_backups,
                args.keep_monthly_backups,
                reference_date
            )

            to_keep = [b for b in remote_backups if b['filename'] in keep_set]
            to_delete = [b for b in remote_backups if b['filename'] not in keep_set]

            # Show directory listing if requested
            if args.list:
                print_backup_directory(remote_backups, keep_reasons, "Remote Backup Directory (S3)")

            print(f"\nKeeping: {len(to_keep)} backup(s)")
            for backup in to_keep:
                dt = backup['datetime']
                types = ','.join(sorted(keep_reasons.get(backup['filename'], set())))
                print(f"  KEEP: {backup['filename']} [{get_day_key(dt)}] [Week {get_week_key(dt)}] ({types})")

            if to_delete:
                print(f"\nDeleting: {len(to_delete)} backup(s)")
                for backup in to_delete:
                    delete_remote_backup(backup, args.dry_run)
                    total_deleted += 1
            else:
                print("\nNo backups to delete.")

            total_kept += len(to_keep)
        else:
            print("No remote backups found.")

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"Total kept: {total_kept}")
    print(f"Total deleted: {total_deleted}" + (" (dry run)" if args.dry_run else ""))
    print("=" * 60)


if __name__ == '__main__':
    main()
