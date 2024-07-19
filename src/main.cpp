#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <cstring>

//пример использования ./tcp_count tests/test1.pcap -s 55104 -d 443
 
int main(int argc, char *argv[]) {
  if (!(argc == 2 || argc == 4 || argc == 6)) {
    std::cout << "Ошибка. Некорректные входные данные.\n"
              << "Пример использования : " << argv[0] << " <pcap file> [-s <source port>] [-d <destination port>]\n";
    return 0;
  }

  char err_buffer[PCAP_ERRBUF_SIZE];
  char *file = argv[1];

  int src_target = -1;
  int dst_target = -1;

  bool filter_mode = false;

  for (int i = 2; i < argc; i += 2) {
    if (strcmp(argv[i], "-s") == 0) {
      src_target = std::atoi(argv[i + 1]);
      filter_mode = true;
    } else if (strcmp(argv[i], "-d") == 0) {
      dst_target = std::atoi(argv[i + 1]);
      filter_mode = true;
    } else {
      std::cout << "Ошибка. Некорректные входные данные: " << argv[i] << "\n";
      return 0;
    }
  }

  pcap_t *handle = pcap_open_offline(file, err_buffer);

  if (handle == nullptr) {
    std::cout << "Ошибка при открытии файла : " << file << " : " << err_buffer << std::endl;
    return 1;
  }

  pcap_pkthdr *header;
  const u_char *packet;
  int tcp_total = 0,tcp_filtred_total = 0;

  while (pcap_next_ex(handle, &header, &packet) >= 0) {
    ip *ip_header = (ip *)(packet + 14);
    if (ip_header->ip_p == IPPROTO_TCP) {
      tcphdr *tcp_header = (tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
      int src_port = ntohs(tcp_header->source);
      int dst_port = ntohs(tcp_header->dest);

      tcp_total++;

      if (filter_mode && (src_port == src_target || src_target == -1) && (dst_port == dst_target || dst_target == -1))
        tcp_filtred_total++;
    }
  }

  pcap_close(handle);

  std::cout << "Найдено " << tcp_total << " TCP пакетов\n";
  if (filter_mode) std::cout << "Найдено " << tcp_filtred_total << " Отфильтрованных" << " TCP пакетов\n";

  return tcp_total;
}