# ctf-managing-tool

CMate is a Python-based command-line utility designed to help cybersecurity enthusiasts and professionals manage their CTF challenges efficiently. It provides functionalities to track, organize, and clean up CTF challenges, making it easier to focus on solving them without worrying about file clutter or losing track of completed tasks.

## Documentation Comment

This repository provides scripts and notes for Capture The Flag (CTF) competitions.
    It includes Python scripts for solving challenges, write-ups, and utilities for common CTF tasks.

## How to use:
 - Clone the repository.
 - Browse the scripts and notes to assist with CTF challenges.
 - Refer to the documentation for usage instructions.

This repository contains scripts and notes related to Capture The Flag (CTF) challenges. It is intended to help automate tasks, document solutions, and organize information during CTF competitions.

## Notes

## The default known ctf box categories are the following
```json
{
  "challenges": [
    "HTB",
    "THM",
    "PICO",
    "VHUB"
  ]
}
```
## You can add to this list with -a flag 
```bash
cmate -a new-category
```

## This script assumes you have your ctf challenge directory under the < ctfs > parent directory then ctf categories vhub,htb,thm...  
```bash
$HOME/somethingHere/ctfs/category/ # Then your challenges
```
You can provide your own parent dir as well with -p flag 

## Read the -h help message for more information about the script
```bash
cmate -h
usage: cmate [-h] [-s Suffix] [-p Parent directory] [-c check] [-d Difficulty] [--create ] [--other other[OTHER ...]] [-i NAME CATEGORY] [-a Add]

CMate: Manage CTF challenges with directory setup, tracking, and cleanup

options:
  -h, --help            show this help message and exit
  -s Suffix, --suffix SUFFIX
                        Suffix to add for completed challenges, Default is done
  -p Parent dir, --parent-dir Parent dir
                        Parent directory for CTF challenges, Default is ctfs/
  -c Check, --check Check
                        Check if challenge name exists in config file, provide challenge name
  -d Difficulty, --difficulty Difficulty
                        Enter the difficulty for the challenge (optional)
  --create [CREATE]     Create scanning scripts in script directory if not exists
  --other OTHER [OTHER ...]
                        Enter other attributes regarding the challenge, separated by commas
  -i NAME CATEGORY, --init NAME CATEGORY
                        To initialize a new challenge. provide challenge name and category < htb, thm, vhub ...>
  -a Add, --add Add     Add a new challenge type
```

## Contributing

Feel free to submit pull requests or open issues to improve the scripts and documentation.

## License

This project is licensed under the MIT License.

---

## 🚀 Features
- ✅ Provides basic and complex ctf functionalities
- ⚡ Fast, lightweight, easy to use
- 🔒 Secure and reliable ctf challenge handling
- Saves list of challenges or ctf boxs you've completed in a json file
- Generates reverse shell payloads and puts them on your box directory

---

## 📦 Installation and Usage

```bash
# Clone the repo
git clone https://github.com/malale21/ctf-managing-tool.git

# Enter the project folder
cd ctf-managing-tool

# Install dependencies (example for Python)
pip install -r requirements.txt

# Add the cmate.py file to your path (optional)
sudo ln -sf ./cmate.py  /usr/sbin/cmate

# In your Challenge directory run cmate
cmate


