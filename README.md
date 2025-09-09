# ctf-managing-tool

CMate is a Python-based command-line utility designed to help cybersecurity enthusiasts and professionals manage their CTF challenges efficiently. It provides functionalities to track, organize, and clean up CTF challenges, making it easier to focus on solving them without worrying about file clutter or losing track of completed tasks.

# Documentation Comment

# This repository provides scripts and notes for Capture The Flag (CTF) competitions.
# It includes Python scripts for solving challenges, write-ups, and utilities for common CTF tasks.
#
# How to use:
# - Clone the repository.
# - Browse the scripts and notes to assist with CTF challenges.
# - Refer to the documentation for usage instructions.

This repository contains scripts and notes related to Capture The Flag (CTF) challenges. It is intended to help automate tasks, document solutions, and organize information during CTF competitions.

## Notes

# This script assumes you have your ctf challenge directory as follows 
```bash
$HOME/challenges/ctfs/- # then your challenges
```
You can provide your source dir as well with -d flag 

# Also the default of known ctf box categories are 
```json
challenges{
    "VHUB","HTB","PICO","THM"
} 
```
You can add to this list with -a flag 



## Contributing

Feel free to submit pull requests or open issues to improve the scripts and documentation.

## License

This project is licensed under the MIT License.

# Project Name

A short, punchy description of what your project does.

---

## 🚀 Features
- ✅ Provides basic and complex ctf functionalities
- ⚡ Fast, lightweight, easy to use
- 🔒 Secure and reliable ctf challenge handling
- Saves list of challenges or ctf boxs you've completed in a json file
- Generates reverse shell payloads and puts them on your machine

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
ln -sf ./cmate.py  /usr/sbin/cmate

# In your Challenge directory run cmate
cmate


