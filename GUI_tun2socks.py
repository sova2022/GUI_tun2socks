#!/usr/bin/env python3

import ttkbootstrap as ttk
from   ttkbootstrap.constants import *
from   tkinter import messagebox
import sys
import os
import ctypes
import re
import time
import requests
from   datetime import datetime
from   subprocess import Popen, PIPE, DEVNULL
import psutil
import webbrowser
from   platform import platform


# CONSTANTS & SETTINGS
PROGRAM_NAME = 'GUI for Tun2Socks v. 1.0'
T2S_VERSION  = 'tun2socks version 2.5.1'
IP_INI_VAL = '127.0.0.1'
PORT_INI_VAL = '1080'
PADX=10
PADY=10
fname='proxy.txt'
WAIT_BAT_TIME = 5    # Time to wait for batch file complit
PROXY_CHECK_TIMEOUT = 5    # Time we wait for proxy response
CHECK_PROXY_AT_ANY_TIME_CB_CLICKED = 'no'
SHOW_FRAMES = 'no'

# Global variables
ip_pattern = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
ipv4_pattern = re.compile("^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def is_admin():
    try:
        # only windows users with admin privileges can read the C:\windows\temp
        temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
    except:
        if messagebox.askyesno("Admin rights required!",\
                "Program manipulates the network interfaces and routing tables. \
You need to grant admin permissions for proper functionality. \
Are you ready to do this right now?"):
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return True    # We are not admin, but will show interface to user anywa
        else:
            return True        # We are not admin, but will show interface to user anyway
    else:
        return True            # We are admin


def on_closing():
    global p
    # Ack for confirmation
    if p: 
        if not messagebox.askokcancel("Quit", "Tun2socks still running! Do you want to quit?"):
            return 0    # Cancel exit

    # Stop tun2socks if running
    if p:
        _stop()
    save_vars()
    logger('Goodby!')
    root.destroy()


# Save proxy parameters to file
def save_vars():
    f = open(fname, 'w')
    f.write(ip_var.get() + ',')
    f.write(port_var.get() + ',')
    f.write(dns1_var.get() + ',')
    f.write(dns2_var.get() + ',')
    f.write(login_var.get() + ',')
    f.write(passwd_var.get() + ',')
    f.write(str(check_proxy_cb_var.get()) + ',')
    f.write(str(dns_cb_var.get()))
    f.close()
    return 0


# Restore proxy and DNS parameters form file
def restore_vars():
    if os.path.isfile(fname):
        f = open(fname, 'r')
        all_val = f.readline()
        all_split = all_val.split(',')
        if len(all_split) == 8:
            ip_var.set(all_split[0])
            port_var.set(all_split[1])
            dns1_var.set(all_split[2])
            dns2_var.set(all_split[3])
            login_var.set(all_split[4])
            passwd_var.set(all_split[5])
            check_proxy_cb_var.set(int(all_split[6]))
            dns_cb_var.set(int(all_split[7]))
            dns_cb_clicked()    # hide DNS if chechbox not checked
        else:
            f.close()
            return 2
        f.close()
    else:
        return 1
    return 0


def hide_widgets():
    for child in fr_proxy.winfo_children():
        child.configure(state='disabled')
    bt_start.configure(state='disabled')

def show_widgets():
    for child in fr_proxy.winfo_children():
        child.configure(state='normal')
    bt_start.configure(state='normal')
    dns_cb_clicked()

def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()


def call_bat(*args, message):
    logger(message, newline=False)
    a = list(args)   # List of batch file name and all parameters
    pp = Popen(a, shell=True, stdout=PIPE, stderr=PIPE)
    try:
        pp.wait(WAIT_BAT_TIME)
        if int(pp.returncode):
            logger(f'Fail: BAT script {a[0]} returned error code: {pp.returncode}', color='red', date=False)
            logger('Make sure you have administrator privileges!', color='red')
            return 1
        logger('DONE', color='green', date=False)
        return 0
    except:
        logger(f'Fail: BAT script {a[0]} not responding', color='red', date=False)
        return 2
    return 3    # Should never get to this point in the program!


def callback(event):
        webbrowser.open_new(event.widget.link)


def check_ip_format(event):
    ip_var = event.widget['textvariable']
    ip = root.globalgetvar(ip_var)
    if not ipv4_pattern.match(ip):
        messagebox.showerror("Error", f"Incorrect IP address: {ip}\nShould be in range: 0.0.0.0 ... 255.255.255.255")
        event.widget.focus_set()


def check_port_format(event):
    port_var = event.widget['textvariable']
    port_str = root.globalgetvar(port_var)
    port = -1
    if port_str.isdigit():
        port = int(port_str)
    if not 1 <= port <= 65535:
        messagebox.showerror("Error", f"Incorrect port number: {port_str}\nShould be in range 1..65535")
        event.widget.focus_set()
        
    # print(port, type(port))
    # if not ipv4_pattern.match(ip):
    #     messagebox.showerror("Error", f"Incorrect IP address: {ip}")
    #     event.widget.focus_set()

def logger(message, newline=True, date=True, color='black'):
    text_log['state'] = NORMAL
    date_str = datetime.now().__str__().split('.')[0]
    date_str = date_str.replace('-', '/')
    if date:
        text_log.insert(ttk.END, date_str + ' ' +  message, color)
    else:
        text_log.insert(ttk.END, message, color)
    if newline:
        text_log.insert(ttk.END, '\n', color)

    text_log.see(ttk.END)
    text_log['state'] = ttk.DISABLED
    root.update_idletasks()


def proxy_check():
    # Get proxy parameters
    ip = ip_var.get()
    port = port_var.get()
    login = login_var.get()
    passwd = passwd_var.get()

    # Set socks5 string
    if login:
        socks5 = f'socks5://{login}:{passwd}@{ip}:{port}'
    else:
        socks5 = f'socks5://{ip}:{port}'

    logger('Checking proxy ... ', newline=False)

    proxies = {'http':f'{socks5}', 'https':f'{socks5}'}
    url1 = 'http://2ip.ru'
    url2 = 'http://ifconfig.me'
    headers={"User-Agent":"curl/7.47.0"}

    res = None
    # Chech proxy with GET request to two url's
    try:
        res = requests.get(url1, proxies=proxies, headers=headers, timeout=PROXY_CHECK_TIMEOUT)
    except:
        pass
    if not res:
        try:
            res = requests.get(url2, proxies=proxies, headers=headers, timeout=PROXY_CHECK_TIMEOUT)
        except:
            pass

    if res:
        logger('OK', date=False, color='green')
    else:
        logger('FAIL', date=False, color='red')

    return res


def start():
    logger('Starting ...')

    hide_widgets()

    # Get parameters from form
    ip = ip_var.get()
    port = port_var.get()
    login = login_var.get()
    passwd = passwd_var.get()
    dns1 = dns1_var.get()
    dns2 = dns2_var.get()
    
    # Check proxy if needed
    if check_proxy_cb_var.get() == 1:
        if not proxy_check():
            show_widgets()
            return 1

    # Make socks5 string
    if login:
        socks5 = f'socks5://{login}:{passwd}@{ip}:{port}'
    else:
        socks5 = f'socks5://{ip}:{port}'

    global p
    p = Popen(['tun2socks-windows-amd64.exe', '-loglevel', 'silent', '-device', 'tun://gateway', '-proxy', socks5], shell=True, stdout=DEVNULL, stderr=DEVNULL)

    # Get log string from tun2socks
    # # log_msg = p.stderr.readline().decode('cp866')
    # # if 'Failed' in log_msg:
    # #     logger('Failed to start tun2socks process!', color='red')
    # #     logger('Make sure you have administrator privileges!', color='red')
    # #     # if not p.returncode:    # If tun2socks still running, kill it
    # #         # kill(p)
    # #     p = None
    # #     show_widgets()
    # #     return 1
    # # else:
    # #     # Print two log strings from tun2socks
    # #     logger(log_msg, newline=False, date=False)
    # #     log_msg = p.stderr.readline().decode('cp866')
    # #     logger(log_msg, newline=False, date=False)

    # Time delay before setting routes. Not needed actually
    time.sleep(1)
    # If tun2socks running
    if not p.returncode:    # If tun2socks still running normaly
        # Start_b.bat
        if dns_cb_var.get() == 1:
            err = call_bat('start_b.bat', f'{ip}', f'{dns1}', f'{dns2}', message='Setting routes and DNS ... ')
        else:
            err = call_bat('start_b.bat', f'{ip}', message='Setting routes ... ')

        if err:
            if not p.pid:
                kill(p.pid)
            p = None
            # Flush_out
            if dns_cb_var.get() == 1:
                err = call_bat('flush_out.bat', f'{ip}', f'{dns1}', f'{dns2}', message='Flush out ... ')
            else:
                err = call_bat('flush_out.bat', f'{ip}', message='Flush out ... ')
            show_widgets()
            return 1
    else:
        # logger('tun2socks terminated unexpectedly!', color='red')
        logger('Failed to start tun2socks process!', color='red')
        logger('Make sure you have administrator privileges!', color='red')
        # Flush_out
        if dns_cb_var.get() == 1:
            err = call_bat('flush_out.bat', f'{ip}', f'{dns1}', f'{dns2}', message='Flush out ... ')
        else:
            err = call_bat('flush_out.bat', f'{ip}', message='Flush out ... ')
        show_widgets()
        return 1

    logger('Tun2socks SUCCESSFULLY STARTED!', color='green')
    return 0


# Stops tun2socks and make flush out
def _stop():
    ip = ip_var.get()
    dns1 = dns1_var.get()
    dns2 = dns2_var.get()
    global p
    if p:
        kill(p.pid)
        p = None
        logger('Terminating tun2socks process')

        # Flush_out
        if dns_cb_var.get() == 1:
            err = call_bat('flush_out.bat', f'{ip}', f'{dns1}', f'{dns2}', message='Flush out ... ')
        else:
            err = call_bat('flush_out.bat', f'{ip}', message='Flush out ... ')
    else:
        logger('tun2socks not started', color='red')
        show_widgets()
        return 1

    logger('Tun2socks TERMINATED!', color='green')
    show_widgets()
    return 0


# 'Stop' button pressed
def stop():
    _stop()


# 'Exit' button pressed
def exit():
    on_closing()


def dns_cb_clicked():
    state = dns_cb_var.get()
    if state:
        en_dns1['state'] = ttk.NORMAL
        en_dns2['state'] = ttk.NORMAL
    else:
        en_dns1['state'] = ttk.DISABLED
        en_dns2['state'] = ttk.DISABLED


def proxy_cb_clicked():
    if CHECK_PROXY_AT_ANY_TIME_CB_CLICKED.lower() == 'yes':
        if check_proxy_cb_var.get() == 1:
            proxy_check()

# Program starts here

if is_admin():

      ############# 
     ##           ##
    ### GUI SETUP ###
     ##           ##
      #############

    p = None    # tun2socks process

    root = ttk.Window(themename='minty')
    root.title(PROGRAM_NAME)
    root.geometry('700x400')

    if SHOW_FRAMES.lower() == 'yes':
        # For test purposes
        fr_main = ttk.Frame(master=root, borderwidth=3, relief=ttk.GROOVE)
        fr_proxy = ttk.Frame(master=fr_main, borderwidth=3, relief=ttk.GROOVE)
        fr_log = ttk.Frame(master=fr_main, borderwidth=3, relief=ttk.GROOVE)
        fr_control = ttk.Frame(master=fr_main, borderwidth=3, relief=ttk.GROOVE)
        fr_info = ttk.Frame(master=fr_main, borderwidth=3, relief=ttk.GROOVE)
        fr_version = ttk.Frame(master=fr_main, borderwidth=3, relief=ttk.GROOVE)
    else:
        fr_main = ttk.Frame(master=root)
        fr_proxy = ttk.Frame(master=fr_main)
        fr_log = ttk.Frame(master=fr_main)
        fr_control = ttk.Frame(master=fr_main)
        fr_info = ttk.Frame(master=fr_main)
        fr_version = ttk.Frame(master=fr_main)

    ##############
    # Left frame #
    ##############

    # IP entry
    ip_var = ttk.StringVar(root, value=IP_INI_VAL)
    en_ip = ttk.Entry(master=fr_proxy, textvariable=ip_var, width = 16)
    en_ip.bind("<FocusOut>", check_ip_format)

    # Port entry
    port_var = ttk.StringVar(root, value=PORT_INI_VAL)
    en_port = ttk.Entry(master=fr_proxy, textvariable=port_var, width=6)
    en_port.bind('<FocusOut>', check_port_format)

    # Login entry
    login_var = ttk.StringVar(root)
    en_login = ttk.Entry(master=fr_proxy, textvariable=login_var, width = 16)

    # Password entry
    passwd_var = ttk.StringVar(root)
    en_passwd = ttk.Entry(master=fr_proxy, textvariable=passwd_var, show='*', width = 16)

    # Labels
    lb_proxy = ttk.Label(master=fr_proxy, text='Proxy address')
    lb_port = ttk.Label(master=fr_proxy, text='Port', justify=ttk.LEFT)
    lb_dns = ttk.Label(master=fr_proxy, text='DNS', justify=ttk.LEFT)
    lb_dns1 = ttk.Label(master=fr_proxy, text='DNS1')
    lb_check_proxy = ttk.Label(master=fr_proxy, text='Check proxy', justify=ttk.CENTER)
    lb_login = ttk.Label(master=fr_proxy, text='\nLogin')
    lb_passwd = ttk.Label(master=fr_proxy, text='\nPassword')
    lb_dns2 = ttk.Label(master=fr_proxy, text='\nDNS2')


    # Check boxes
    dns_cb_var = ttk.IntVar()
    cb_dns = ttk.Checkbutton(master=fr_proxy, text='',variable=dns_cb_var, onvalue=1, offvalue=0, command=dns_cb_clicked)
    check_proxy_cb_var = ttk.IntVar()
    cb_check_proxy = ttk.Checkbutton(master=fr_proxy, text='',variable=check_proxy_cb_var, onvalue=1, offvalue=0, command=proxy_cb_clicked)

    # DNS entries
    dns1_var = ttk.StringVar(root, value='1.1.1.1')
    en_dns1 = ttk.Entry(master=fr_proxy, textvariable=dns1_var, width=16, state=ttk.DISABLED)
    en_dns1.bind("<FocusOut>", check_ip_format)
    dns2_var = ttk.StringVar(root, value='1.0.0.1')
    en_dns2 = ttk.Entry(master=fr_proxy, textvariable=dns2_var, width=16, state=ttk.DISABLED)
    en_dns2.bind("<FocusOut>", check_ip_format)

    # Log
    text_log = ttk.Text(master=fr_log, state=ttk.DISABLED)
    text_log.tag_config('red', foreground='red')
    text_log.tag_config('blue', foreground='blue')
    text_log.tag_config('green', foreground='green')

    # Buttons
    bt_start = ttk.Button(master=fr_control, text = 'Start',bootstyle=PRIMARY, command = start)
    bt_stop = ttk.Button(master=fr_control, text = 'Stop', bootstyle=DANGER, command = stop)
    bt_exit = ttk.Button(master=fr_control, text = 'Exit', command = exit, bootstyle=(INFO, OUTLINE))


    ################
    # PACK WIDGETS #
    ################

    # Main frames
    fr_main.master.columnconfigure(0, weight=1)
    fr_main.master.rowconfigure(0, weight=1)
    fr_main.grid(row=0, column=0, sticky='EWNS', padx=2*PADX, pady=PADY//2)
    fr_main.columnconfigure(0, weight=1)
    fr_main.columnconfigure(1, weight=2)
    fr_main.rowconfigure(0, weight=0)
    fr_main.rowconfigure(1, weight=1)

    fr_proxy.grid(row=0, column=0, sticky='w')
    fr_log.columnconfigure(0, weight=1)
    fr_log.rowconfigure(0, weight=1)
    fr_log.grid(row=1, column=0, sticky='nswe', padx=PADX, pady=PADY) 

    fr_info.columnconfigure(0, weight=1)
    fr_info.rowconfigure(0, weight=1)
    fr_info.grid(row=0, column=1, sticky='new', rowspan=3, padx=PADX)
    fr_control.grid(row=2, column=0, sticky='w')

    # fr_version.rowconfigure(0, weight=1)
    fr_version.grid(row=2, column=1, sticky='se')

    ### Proxy frame ###
    lb_proxy.grid(row=0,column=0, sticky='w', padx=PADX)
    lb_port.grid(row=0,column=1, sticky='w', padx=PADX)
    lb_check_proxy.grid(row=0, column=2, padx=PADX)
    lb_dns.grid(row=0,column=3, sticky='w')
    lb_dns1.grid(row=0,column=4, sticky='w', padx=PADX)

    en_ip.grid(row=1, column=0)
    en_port.grid(row=1, column=1, padx=PADX, sticky='w')
    cb_check_proxy.grid(row=1, column=2)
    cb_dns.grid(row=1, column=3)
    en_dns1.grid(row=1, column=4, sticky='w', padx=PADX)

    lb_login.grid(row=2, column=0, sticky='w', padx=PADX)
    lb_passwd.grid(row=2, column=1, sticky='w', padx=PADX)
    lb_dns2.grid(row=2, column=4, sticky='w', padx=PADX)

    en_login.grid(row=3, column=0, sticky='w', padx=PADX)
    en_passwd.grid(row=3, column=1,columnspan=2, sticky='w', padx=PADX)
    en_dns2.grid(row=3, column=4, sticky='w', padx=PADX)

    # Log frame
    text_log.grid(row=0, column=0, sticky='NEWS')

    # Buttons frame
    bt_start.grid(row=0, column=0, padx=20, pady=10)
    bt_stop.grid(row=0, column=1, padx=20, pady=10)
    bt_exit.grid(row=0, column=2, padx=20, pady=10)


    ##############
    # Info frame #
    ##############

    lb_info1   = ttk.Label(master=fr_info, text="Mobile proxies with\nWindows's Passive\nOS fingerprint", justify=CENTER)
    lb_info2   = ttk.Label(master=fr_info, text=r"arbitrage-bets.com", foreground="blue", cursor="hand2")
    lb_info2.link = r'https://arbitrage-bets.com/proxy?bets=LU5QXHCKy'
    lb_info2.bind("<Button-1>", callback)

    lb_t2s_version = ttk.Label(master=fr_version, text=T2S_VERSION, justify=RIGHT)

    lb_contact1 = ttk.Label(master=fr_info, text='IP Auditor')
    lb_contact2 = ttk.Label(master=fr_info, text='detect.expert', foreground="blue", cursor="hand2")
    lb_contact2.link = r'http://favoritesoftware.top/a85afcwe9zow'
    lb_contact2.bind("<Button-1>", callback)
    lb_blank0 = ttk.Label(master=fr_info, text='\n')
    lb_blank1 = ttk.Label(master=fr_info, text='')
    lb_blank2 = ttk.Label(master=fr_info, text='')

    lb_tg1 = ttk.Label(master=fr_info, text='support')
    lb_tg2 = ttk.Label(master=fr_info, text='@GUI_support', foreground="blue", cursor="hand2")
    lb_tg2.link = r'https://t.me/GUI_support'
    lb_tg2.bind("<Button-1>", callback)

    lb_blank0.grid(row=0, column=0, sticky='n')
    lb_info1.grid(row=1, column=0, sticky='n')
    lb_info2.grid(row=2, column=0, sticky='n')
    lb_blank1.grid(row=3, column=0, sticky='n')
    lb_contact1.grid(row=4, column=0, sticky='n')
    lb_contact2.grid(row=5, column=0, sticky='n')
    lb_blank2.grid(row=6, column=0, sticky='n')
    lb_tg1.grid(row=7, column=0, sticky='n')
    lb_tg2.grid(row=8, column=0, sticky='n')

    lb_t2s_version.grid(row=0, column=0, sticky='s')

    if not 'linux' in platform().lower():
        basedir = os.path.dirname(__file__)
        root.iconphoto(False, ttk.PhotoImage(file=os.path.join(basedir, "icon.png")))
    restore_vars()
    root.protocol("WM_DELETE_WINDOW", on_closing)

    # fix appearance in the background when no admin permissions
    root.attributes("-topmost", True)
    root.attributes("-topmost", False)
    root.mainloop()

else:
    # Re-run the program with admin rights
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
