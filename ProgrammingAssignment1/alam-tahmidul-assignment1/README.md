**PART A**
(TESTED IN GOOGLE CHROME)
    -> In order to run Part A, the following information must be known:
        - IPV4 Address of the local machine, the port you want to use, (and a default html file (optional) otherwise you'll load with a 404 Page)
            * Open your Command Prompt and search the IPV4 address using ipconfig (Windows)
            * In webserver.py, change the value `localAddr` to this IPV4 address
            * Choose any port number for `serverPort`
            * (Optional) Create a blank HTML page and place it in the same directory. Then change the `indexFile` to the location of the saved HTML (i.e. if ``index.html`` is on the same directory as `webserver.py`, then set `indexFile = "index.html"`)
    
    -> To run the program, open up command prompt, change directory to this folder, and type `python webserver.py`
    -> Open up a browser and type your IP Address followed by the port shown in terminal
        * If your command prompt says, `Server running on  ('127.0.0.1', 5000)`, then in the URL, type `127.0.0.1:5000`
    -> Use the URL to place the names of files like this: `127.0.0.1:5000/file.html`

    --> To close, you can press Ctrl+C on Windows (and its equivalent on other OS) then refresh the browser to stop the process
        --> Otherwise, kill the process

**PART B**
(TESTED IN GOOGLE CHROME)
    -> In order to run Part B, the following information must be known:
        - IPV4 Address of the local machine, the port you want to use
            * Open your Command Prompt and search the IPV4 address using ipconfig (Windows)
            * In proxyserver.py, change the value `serverName` to this IPV4 address
            * Choose any port number for `serverPort`
    
    -> To run the program, open up command prompt, change directory to this folder, and type `python proxyserver.py`
    -> Open up a browser and type your IP Address followed by the port shown in terminal
        * If your command prompt says, `Proxy Server 10.0.0.0 listening on port 4080: http://10.0.0.0:4080`, then in the browser URL, type `10.0.0.0:4080`
    -> Use the URL to place the names of some websites to cache: `10.0.0.0:4080/www.x.com`

    -- NOTE --
    -> The URL to place the URLs of websites must start with www. (i.e. www.google.com and not google.com)
    -> The cache gets stored in a local .txt file in the same directory. On refresh, `proxyserver.py` loads the code from local directory
    -> The following websites work with Part B
        - www.example.com
        - www.google.com
        - www.x.com
        --> Some of the websites like www.yahoo.com, www.something.com gave a 301 Redirect error
        --> Others don't load at all: gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file2.html
        --> Other website gives a 404 error
    --> Once you have gone to a new website, refresh the page to add to cache (if not added)
    --> To close, you can press Ctrl+C on Windows (and its equivalent on other OS) then refresh the browser to stop the process
        --> Otherwise, kill the process