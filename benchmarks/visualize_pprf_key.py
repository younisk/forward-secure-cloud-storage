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
from ete3 import Tree, TreeStyle, TreeNode, NodeStyle
import ctypes
import pickle


def progressbar(it, prefix_progbar="", size=60, out=sys.stdout):  # Python3.3+
    count = len(it)

    def show(j):
        x = int(size * j / count)
        print("{}[{}{}] {}/{}".format(prefix_progbar, "#" * x, "." * (size - x), j, count),
              end='\r', file=out, flush=True)

    show(0)
    for i, item in enumerate(it):
        yield item
        show(i + 1)
    print("\n", flush=True, file=out)


def read_key_test(path):
    list_of_prefixes = ["1" * j + "0" for j in range(1, 10)]
    list_of_prefixes.append("0001")
    list_of_prefixes.append("01")
    list_of_prefixes.append("001")
    return list_of_prefixes


# does the same as PPRFKeySerializer in deserialize
def read_key(path):
    with open(path, 'rb') as serializedKey:
        tag_size = int.from_bytes(serializedKey.read(ctypes.sizeof(ctypes.c_uint64)), "big")
        key_size = int.from_bytes(serializedKey.read(ctypes.sizeof(ctypes.c_uint64)), "big")

        puncs = int.from_bytes(serializedKey.read(ctypes.sizeof(ctypes.c_uint64)), "big")
        numNodes = int.from_bytes(serializedKey.read(ctypes.sizeof(ctypes.c_uint64)), "big")

        prefixes = []
        for nodeIndex in range(numNodes):
            prefix_size = int.from_bytes(serializedKey.read(ctypes.sizeof(ctypes.c_size_t)), "big")
            p = serializedKey.read(prefix_size).decode('ascii')
            prefixes.append(p)
            serializedKey.read(key_size // 8)  ## key_size
        print("Found", len(prefixes), "prefixes.")
        print("Remaining bytes in serialized key:", len(serializedKey.read()))
        return prefixes


grey_node_style = NodeStyle({
    "fgcolor": 'lightgrey',
    "size": 5})
key_node_style = NodeStyle({
    "fgcolor": 'limegreen',
    "size": 5})


# Can visualize a serialized PPRF secret key (lib-puncturable-key-wrapping-cpp/pkw/pprf/ggm_pprf_key.h)
# File path of serialized key must be provided as argument.
if __name__ == '__main__':
    tree = Tree()
    tree.set_style(grey_node_style)
    if len(sys.argv) > 1:
        prefixes = read_key(sys.argv[1])
        name = sys.argv[1].split('/')[-1].split('.')[0]
        print("Building tree.")
        for prefix in progressbar(prefixes):
            parent = tree
            for sub_length in range(1, len(prefix) + 1):
                sub_prefix = prefix[:sub_length]
                # matching_leaves = node.search_nodes(name=sub_prefix)
                if len(list(x for x in parent.children if x.name == sub_prefix)) == 0:
                    # insert the leaf and its sibling
                    # parent_name = sub_prefix[:-1]
                    # parents = node.search_nodes(name=parent_name)
                    # assert len(parents) == 1
                    if len(sub_prefix) == len(prefix):
                        n = TreeNode(name=prefix)
                        n.set_style(key_node_style)
                        parent.add_child(n)
                    else:
                        # assert len(parents[0].children) == 0
                        n = TreeNode(name=sub_prefix)
                        n.set_style(grey_node_style)
                        parent.add_child(n)
                        parent = n
                else:
                    parent = next(x for x in parent.children if x.name == sub_prefix)

        print("Sorting tree..")
        tree.sort_descendants()
        tree.swap_children()
        for n in tree.iter_descendants():
            n.swap_children()
        print("Dumping pickle..")
        with open(name + ".pkl", "wb") as t:
            pickle.dump(tree, t, -1)
    else:
        print("Loading tree from path..")
        with open("mytree.pkl", "rb") as t:
            tree = pickle.load(t)
    ts = TreeStyle()
    ts.show_leaf_name = False
    ts.rotation = 90
    ts.branch_vertical_margin = 7
    ts.show_scale = False
    ts.scale = 20
    print("Rendering tree...")
    tree.render("mytree.png", tree_style=ts, h=400, units='mm')
    # print(tree.get_ascii())