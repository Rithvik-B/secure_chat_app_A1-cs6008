# Phase 5 — Key-rotation fingerprint timeline (assignment §6.2)

Each rotation produces a fresh, independent key. Both clients log the new epoch's fingerprint with a timestamp; the fingerprint changes every rotation and the two clients always agree.

```
epoch time (alice)  alice fingerprint   time (bob)    bob fingerprint     match 
--------------------------------------------------------------------------------
0     07:22:40      edadeade4196261a    07:22:40      edadeade4196261a    yes   
1     07:23:01      d5b9d6fbd2bad80f    07:23:01      d5b9d6fbd2bad80f    yes   
2     07:23:21      0ab850ced4712d7f    07:23:21      0ab850ced4712d7f    yes   
```

Two rotations (epoch 0 -> 1 -> 2): the fingerprint changes each time and matches across the pair. The interval was set to 20 s via `--rekey 20` so the rotations complete within a short captured session; the code default is 60 s as the assignment specifies.