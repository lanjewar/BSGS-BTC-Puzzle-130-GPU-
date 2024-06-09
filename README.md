## Info
```python bsgs_GPU3.py -pubkey 03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852 -n 100000000000000000 -d 0 -t 256 -b 20 -p 1024 -bp 5000000 -keyspace 200000000000000000000000000000000:3ffffffffffffffffffffffffffffffff -rand```  
_This uses a GPU to find privatekey of the given pubkey._  

# Run
```
(base) C:\anaconda3>python bsgs_GPU3.py
usage: bsgs_GPU.py [-h] -pubkey PUBKEY [-n N] [-d D] [-t T] [-b B] [-p P]
                   [-bp BP] [-keyspace KEYSPACE] [-rand] [-rand1]

This tool use bsgs algo for sequentially searching 1 pubkey in the given range

optional arguments:
  -h, --help          show this help message and exit
  -pubkey PUBKEY      Public Key in hex format (compressed or uncompressed)
  -n N                Total sequential search in 1 loop.
                      default=10000000000000000
  -d D                GPU Device. default=0
  -t T                GPU Threads. default=256
  -b B                GPU Blocks. default=20
  -p P                GPU Points per Threads. default=256
  -bp BP              bP Table Elements for GPU. default=2000000
  -keyspace KEYSPACE  Keyspace Range ( hex ) to search from min:max.
                      default=1:order of curve
  -rand               Start from a random value in the given range from
                      min:max and search n values then again take a new random
  -rand1              First Start from a random value, then go fully
                      sequential, in the given range from min:max

Enjoy the program! :) 
Harshal Lanjewar

```
