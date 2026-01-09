import requests
import re
import socket
import threading
import time

proxy = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
    "https://proxyspace.pro/socks4.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt",
    "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all",
    "https://api.openproxylist.xyz/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/socks4.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
]

proxyparse = set()
good_prox = set()
good_prox_lock = threading.Lock()
checked_count = 0
checked_lock = threading.Lock()

def parser(url):
    try:
        response = requests.get(url, headers={
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }, timeout=15)
        
        if response.status_code == 200:
            pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b'
            ip_port_list = re.findall(pattern, response.text)
            
            for proxy_addr in ip_port_list:
                parts = proxy_addr.split(':')
                if len(parts) == 2:
                    ip_parts = parts[0].split('.')
                    if len(ip_parts) == 4 and all(0 <= int(p) <= 255 for p in ip_parts):
                        port = int(parts[1])
                        if 1 <= port <= 65535:
                            proxyparse.add(proxy_addr)
            
            print(f"✓ Парсинг {url}: найдено {len(ip_port_list)}, валидных: {len(proxyparse)}")
        else:
            print(f"✗ Ошибка HTTP {response.status_code} при парсинге {url}")
            
    except requests.exceptions.Timeout:
        print(f"✗ Таймаут при парсинге {url}")
    except requests.exceptions.RequestException as e:
        print(f"✗ Ошибка запроса {url}: {e}")
    except Exception as e:
        print(f"✗ Неизвестная ошибка при парсинге {url}: {e}")

def check_proxy(proxy_address):
    global checked_count
    try:
        ip, port_str = proxy_address.split(':')
        port = int(port_str)
        
        socket.inet_aton(ip) 
        if not (1 <= port <= 65535):
            raise ValueError(f"Неверный порт: {port}")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        start_time = time.time()
        s.connect((ip, port))
        connect_time = time.time() - start_time
        target_host = "142.250.185.78" 
        target_port = 80
        packet = b'\x04\x01' 
        packet += target_port.to_bytes(2, 'big')  
        packet += socket.inet_aton(target_host)  
        packet += b'\x00'  
        
        s.sendall(packet)
        response = s.recv(8)
        s.close()
        
        if len(response) >= 8:
            if response[0] == 0x00 and response[1] == 0x5A:
                with good_prox_lock:
                    good_prox.add(f"{proxy_address}#{connect_time:.2f}s")
                print(f"✓ Валидный прокси: {proxy_address} ({connect_time:.2f}s)")
            else:
                error_codes = {
                    0x5B: "Отклонено или не выполнено",
                    0x5C: "Не удалось соединиться с IDENTD",
                    0x5D: "IDENTD сообщил о разных user ID"
                }
                error_msg = error_codes.get(response[1], f"Неизвестная ошибка: {hex(response[1])}")
                print(f"✗ Невалидный: {proxy_address} - {error_msg}")
        else:
            print(f"✗ Неполный ответ от: {proxy_address}")
            
    except socket.timeout:
        print(f"✗ Таймаут: {proxy_address}")
    except socket.gaierror:
        print(f"✗ Неверный адрес: {proxy_address}")
    except (ConnectionRefusedError, ConnectionResetError):
        print(f"✗ Соединение отклонено: {proxy_address}")
    except ValueError as e:
        print(f"✗ Неверный формат: {proxy_address} - {e}")
    except Exception as e:
        print(f"✗ Ошибка проверки {proxy_address}: {type(e).__name__}")
    finally:
        with checked_lock:
            checked_count += 1

def checker_main():
    print("\n" + "="*50)
    print("🚀 Начинаю проверку SOCKS4 прокси...")
    print(f"📊 Всего для проверки: {len(proxyparse)} прокси")
    print("="*50 + "\n")
    
    start_time = time.time()
    threads = []
    max_threads = 200  
    
    for proxy_address in list(proxyparse):
        while threading.active_count() > max_threads:
            time.sleep(0.1)
        
        thread = threading.Thread(target=check_proxy, args=(proxy_address,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    total_time = time.time() - start_time
    
    print("\n" + "="*50)
    print("✅ Проверка завершена!")
    print(f"⏱ Время выполнения: {total_time:.2f} секунд")
    print(f"📊 Проверено: {checked_count} прокси")
    print(f"✅ Рабочих: {len(good_prox)} прокси")
    print("="*50)

if __name__ == "__main__":
    print("🌐 Начинаю парсинг источников прокси...")
    
    parse_threads = []
    for url in proxy:
        thread = threading.Thread(target=parser, args=(url,))
        parse_threads.append(thread)
        thread.start()
    
    for thread in parse_threads:
        thread.join()
    
    print(f"\n📊 Всего собрано {len(proxyparse)} уникальных прокси")
    
    if proxyparse:
        checker_main()
        
        if good_prox:
            sorted_proxies = sorted(good_prox, key=lambda x: float(x.split('#')[1].replace('s', '')))
            
            with open("socks4_proxies.txt", "w", encoding="utf-8") as f:
                for proxy_info in sorted_proxies:
                    proxy_addr = proxy_info.split('#')[0]
                    f.write(proxy_addr + "\n")
            
            print(f"\n💾 Записано {len(good_prox)} рабочих SOCKS4 прокси в socks4_proxies.txt")
            
            print("📝 Proxies write to socks4_proxies.txt ")
        else:
            print("\n😔 Не найдено рабочих SOCKS4 прокси")
    else:
        print("\n⚠ Не удалось собрать прокси для проверки")