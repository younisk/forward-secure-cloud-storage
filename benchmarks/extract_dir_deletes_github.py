#  Copyright 2023. Younis Khalil
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
#   documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
#   persons to whom the Software is furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
#   Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
#   BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
#   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
import sys
import fs
from fs import errors


def delete_empty_dirs(p):
    dir_path = fs.path.dirname(p)
    # go up in directories and delete all empty ones
    while virt_fs.exists(dir_path) and len(virt_fs.listdir(dir_path)) == 0:
        virt_fs.removedir(dir_path)
        dir_path = fs.path.dirname(dir_path)


def rewrite_delete_run():
    del_dirs = []
    # in first step remove all empty directories from file system
    for p in delete_run:
        delete_empty_dirs(p)

    for p in delete_run:
        parent = fs.path.dirname(p)
        # if parent directory is empty after delete run, a whole directory was deleted
        if not virt_fs.exists(parent):
            # if parent directory is empty, remove it
            while not virt_fs.exists(fs.path.dirname(parent)):
                parent = fs.path.dirname(parent)
            # only add directory delete to list once
            if del_dirs.count(parent) == 0:
                del_dirs.append(parent)
        else:
            # not delete through directory delete, add single delete back to history
            out.write("D\t" + fs.path.relpath(p) + "\n")
    for directory in del_dirs:
        # add directory deletions to history
        out.write("DD\t" + fs.path.relpath(directory) + "\n")

# Reads GitHub history (resources/) and finds sequences of deletions that constitute a directory deletion.
# Outputs file at same location with "_with_dir_deletes" appended to the name.
# call with path of github hist as first argument
if __name__ == '__main__':
    # build in-memory virtual file system
    virt_fs = fs.open_fs("mem://")
    i = 0
    delete_run = []
    errcount = 0
    with open(sys.argv[1].split(".")[0] + "_with_dir_deletes.txt", 'w') as out:
        with open(sys.argv[1], 'r') as f:
            for line in f.readlines():
                try:
                    l = line.split('\t')
                    ac = l[0].strip()
                    file_path = fs.path.abspath(l[1].strip())
                    if virt_fs.exists(file_path) or ac == 'A':
                        if ac == 'D':
                            # if not virt_fs.exists(file_path):
                            #     continue
                            virt_fs.remove(file_path)
                            delete_run.append(file_path)
                        else:
                            if len(delete_run) > 0:
                                # check for each file whether parent still contains something
                                rewrite_delete_run()
                            delete_run.clear()
                            # Actions other than deletions are simply echoed to the new history (if the file exists)
                            if ac == 'A':
                                virt_fs.makedirs(fs.path.dirname(file_path), recreate=True)
                                virt_fs.writetext(file_path, "foobar")
                            elif ac.startswith('R'):
                                file_name_new = (l[2] if ac.startswith('R') else "").strip()
                                virt_fs.makedirs(fs.path.dirname(file_name_new), recreate=True)
                                virt_fs.move(file_path, file_name_new)
                                delete_empty_dirs(file_path)
                            out.write(line)
                    else:
                        print("Could not find file", line.strip(), "in system.")
                        errcount += 1
                except fs.errors.FSError:
                    print("Error while processing line", line.strip())
                    errcount += 1

    # print(virt_fs.tree())

    for directory in virt_fs.walk.dirs():
        if len(virt_fs.listdir(directory)) == 0:
            print("Found empty directory: ", directory)

    print("Number of dirs", len(list(virt_fs.walk.dirs(""))))
    print("Number of faulty lines:", errcount)