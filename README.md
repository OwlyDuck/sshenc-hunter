## SSHenc Hunter

This tool takes the heap of a ssh process and tries to find the sshenc structure, which contains the symetrical keys.

It expects the format of the output of volatility3 when dumping a process, which is

```
pid.<pid>.vma.<heap start address>-<heap end address>.dmp
```

To know which one is the heap, look at procs map