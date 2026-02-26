## 🧰 Base Commands

This document specifies default command usage for Unix environments.

* Change directory
```bash
# Change to the specified directory
cd /directory/
```
* Tool: Bash

* Show current directory
```bash
# Print the current working directory
pwd
```
* Tool: Bash

* Show content of a file
```bash
# Concatenate and print file content to standard output
cat <FILE>
```
* Tool: Bash

* Show first content of a file
```bash
# Output the first 10 lines of a file
head <FILE>
```
* Tool: Bash

* Copy file
```bash
# Copy a source file to a destination path
cp <SOURCE> <DESTINATION>
```
* Tool: Bash

* Move file
```bash
# Move or rename a file
mv <SOURCE> <DESTINATION>
```
* Tool: Bash

* Remove file
```bash
# Force remove a file or directory recursively without prompting
rm -rf <FILE>
```
* Tool: Bash

* Output command to a file
```bash
# Redirect standard output of a command to a file
<COMMAND> > <FILE>
```
* Tool: Bash

## 🗒️ Directory Listing

* Base command
```bash
# List directory contents
ls
```
* Tool: Bash

* Hidden files
```bash
# List all entries including those starting with a dot
ls -a
```
* Tool: Bash

* Show permissions
```bash
# Use a long listing format to view permissions, ownership, and size
ls -l
```
* Tool: Bash

> [!NOTE]
> File type structure: [owner] rwx - [group] rwx - [others] rwx

## 👤 User Management

* Connection history
```bash
# Show a listing of last logged in users
last
```
* Tool: Bash

* Show UID, GID, and groups
```bash
# Print real and effective user and group IDs
id
```
* Tool: Bash

* List user groups
```bash
# Print the specific groups a user belongs to
groups <USERNAME>
```
* Tool: Bash

* Show current username
```bash
# Print effective user ID name
whoami
```
* Tool: Bash

## 🔎 File Searching

* Find file
```bash
# Search for files in a directory hierarchy by exact name
find <DIRECTORY> -name "<FILE-NAME>"
```
* Tool: Bash

> [!TIP]
> Use *.pdf to find all PDF files.
> Use the grep command to filter standard output results.

* Filter result output
```bash
# Parse command output and filter lines matching the specified pattern
<COMMAND> | grep "flag.txt"
```
* Tool: Bash

## 🔐 File Permissions

* Change permissions
```bash
# Grant read, write, and execute permissions to user, group, and others
chmod 777 <FILE>
```
* Tool: Bash

## 🐍 Python Utilities

* Local network file transfer
```bash
# Start a simple HTTP server on port 8000 for easy file sharing
python3 -m http.server
```
* Tool: Bash
