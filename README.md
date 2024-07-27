<img src="https://github.com/NotReallyJustin/GitSniff/blob/main/logo.PNG?raw=true" width="80%" height="auto"/>

## Overview
`gitsniff` is a very simple command line tool that fuzzes Github repositories in search of hidden, deleted, or private forks. <br />
<br />
Or, as of 7/24/2024, `gitsniff` is a (and might be one of the first) tool to launch **Cross Fork Object Reference (CFOR)** attacks. <br />
This 'vulnerability' was discovered two days ago by <a href="https://trufflesecurity.com/blog/anyone-can-access-deleted-and-private-repo-data-github">Truffle Security</a>. 👑 Go check out those guys and give them some well-deserved traffic. <br />
<br />
The general gist is that `gitsniff` exploits how the `git` repository network handles the concept of "upstream" nodes (more specifically, how that node gets reassigned), and how deleting a fork in `git` doesn't actually remove it from the overall `git` tree. <br />
Github is built off `git`. As such, all publicly available `git` repositories are theoretically susceptible to `gitsniff`. <br />
Github is aware of this attack and according to Truffle Security, has no intentions of patching it (it's a feature, not a bug).

## Running gitsniff
First, install the necessary dependencies:
```bash
pip install requests
pip install tqdm
```

To run:
```bash
python ./gitsniff.py -u [Github Repo URL]
ie. python .\gitsniff.py -u https://github.com/NotReallyJustin/Generic-Open-AI-Wrapper
```

For help:
```bash
python ./gitsniff.py -h
```

## Modifying gitsniff
`gitsniff` is nothing groundbreaking. All it really does is fuzz short SHA-1 hashes and uses the Github API to differentiate actual commits from potential, hidden forks. <br />
This tool uses multithreading (via ThreadPoolExecutors). Make sure your computer can handle that. <br /> <br />
Feel free to (funnily enough) clone this. It's dedicated to the public domain, so go have some fun. <br />
<br />
Potential Improvement Ideas:
* Add multiprocessing capabilities (since this *does* do things via brute force)
* Bypass Github's rate limit. I didn't have the time to test this on Proxy Servers or VPNs (since it would be kind of a waste of money to proxy server something that is only going to take 2 hours to run), but that's something you could look into

## Demo/Images of gitsniff in action
Feel free to follow along and run `gitsniff` (and test it) on this <a href="https://github.com/NotReallyJustin/Generic-Open-AI-Wrapper">generic OpenAI wrapper</a>. Don't worry, you have my permission to CFOR that repo. Plus I can't stop you.
<br /><br />
Here's `gitsniff` running:

<br />
Result:
<br />

Clicking into one of the hidden forks (that's now deleted):
<br />
