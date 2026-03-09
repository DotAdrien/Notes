## 🔓 Restricted Shell Bypass

Initial access achieved as user `margaret` on host `DANTE-NIX02` with restricted shell privileges. Enumeration of allowed commands indicates `vim` is available. Utilizing GTFOBins methodology, `vim` can be leveraged to escape the restricted environment and spawn a fully interactive shell. The user flag is located in the home directory.

Execute `vim` from the restricted shell, then enter the following commands within the editor to bypass restrictions:

```vim
# Set the default shell variable and spawn the shell
:set shell=/bin/bash
:shell
```
* Tool: Vim
