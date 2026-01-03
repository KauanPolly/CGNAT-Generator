import ipaddress
from fpdf import FPDF
from fpdf.enums import XPos, YPos

class RelatorioCGNAT(FPDF):
    def header(self):
        # Cabeçalho idêntico ao padrão profissional enviado
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "RELATÓRIO TÉCNICO DE IMPLEMENTAÇÃO - CGNAT", align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f'Pagina {self.page_no()}', align='C')

def gerar_cgnat_final():
    print("=== GERADOR CGNAT DETERMINÍSTICO (ESTRUTURA PDF) ===")
    
    # --- INPUTS ---
    public_net_str = input("Rede Pública (Ex: 143.255.133.0/25): ") or "143.255.133.0/25"
    private_start_str = input("IP Privado Inicial (Ex: 100.64.32.0): ") or "100.64.32.0"
    total_ips_privados = int(input("Total de IPs Privados (Ex: 4096): ") or "4096")
    portas_por_cliente = int(input("Portas por Cliente (Ex: 2016): ") or "2016")

    # --- PROCESSAMENTO ---
    try:
        rede_pub_total = ipaddress.IPv4Network(public_net_str, strict=False)
        ip_priv_ini = ipaddress.IPv4Address(private_start_str)
    except Exception as e:
        print(f"Erro nos IPs: {e}")
        return
    
    porta_ini = 1024
    # Quantos grupos de portas cabem em um único IP público? (Ex: 64512 / 2016 = 32)
    blocos_por_ip = (65536 - porta_ini) // portas_por_cliente

    script_saida = []
    tabela_mapeamento = []

    # Seções Iniciais [cite: 98, 100, 103]
    script_saida.append(f"# RANGE IPS PRIVADOS PARA CGNAT {ip_priv_ini}-{ip_priv_ini + total_ips_privados - 1} | TOTAL DE IPS {total_ips_privados} | PORTAS POR CLIENTE: {portas_por_cliente}")
    script_saida.append("\n#BLACKHOLE")
    script_saida.append(f"/ip/route/add blackhole comment=CGNAT_BLACKHOLE disabled=no dst-address={rede_pub_total}")
    script_saida.append("\n#FASTTRACK")
    script_saida.append("/ip/firewall/filter/add chain=forward action=fasttrack-connection connection-state=established,related hw-offload=yes")
    script_saida.append("/ip/firewall/filter/add chain=forward action=accept connection-state=established,related")
    script_saida.append("\n#CGNAT")
    
    # 1. Gerar Jumps para as redes /24 [cite: 108, 109]
    redes_24_processadas = set()
    for i in range(total_ips_privados):
        ip_v = ip_priv_ini + i
        r24 = str(ipaddress.IPv4Network(f"{ip_v}/24", strict=False).network_address)
        if r24 not in redes_24_processadas:
            chain_name = f"CGNAT_{r24.replace('.', '_')}"
            script_saida.append(f"/ip/firewall/nat/add chain=srcnat src-address={r24}/24 out-interface=\"WAN\" action=jump jump-target={chain_name}")
            redes_24_processadas.add(r24)

    # 2. Gerar Jumps para /25 e Regras Netmap [cite: 1, 114]
    for i in range(0, total_ips_privados, 128):
        bloco_id = i // 128
        ip_bloco_priv_ini = ip_priv_ini + i
        rede_priv_25 = ipaddress.IPv4Network(f"{ip_bloco_priv_ini}/25", strict=False)
        
        # Pega a rede /24 correta para o Jump Nível 2
        rede_mae_24 = str(ipaddress.IPv4Network(f"{ip_bloco_priv_ini}/24", strict=False).network_address)
        chain_mae = f"CGNAT_{rede_mae_24.replace('.', '_')}"
        
        chain_final = f"CGNAT_{bloco_id}"
        script_saida.append(f"/ip/firewall/nat/add chain={chain_mae} src-address={rede_priv_25} action=jump jump-target={chain_final}")
        
        # Cálculo do Range de Portas e IP Público para Netmap
        num_range_porta = bloco_id % blocos_por_ip
        p_start = porta_ini + (num_range_porta * portas_por_cliente)
        p_end = p_start + portas_por_cliente - 1

        # Rotaciona o bloco público se necessário
        offset_pub = (bloco_id // blocos_por_ip) * 128
        base_pub_bloco = rede_pub_total.network_address + (offset_pub % rede_pub_total.num_addresses)
        rede_pub_25_dest = ipaddress.IPv4Network(f"{base_pub_bloco}/25", strict=False)

        # Regras Netmap idênticas ao modelo 
        script_saida.append(f"/ip/firewall/nat/add action=netmap chain={chain_final} protocol=tcp src-address={rede_priv_25} to-addresses={rede_pub_25_dest} to-ports={p_start}-{p_end}")
        script_saida.append(f"/ip/firewall/nat/add action=netmap chain={chain_final} protocol=udp src-address={rede_priv_25} to-addresses={rede_pub_25_dest} to-ports={p_start}-{p_end}")
        script_saida.append(f"/ip/firewall/nat/add action=netmap chain={chain_final} src-address={rede_priv_25} to-addresses={rede_pub_25_dest}")

        # 3. Mapeamento IP por IP para o PDF (Garantindo Sequência)
        for offset in range(128):
            ip_ind_priv = rede_priv_25.network_address + offset
            ip_ind_pub = rede_pub_25_dest.network_address + offset
            if ip_ind_priv < (ip_priv_ini + total_ips_privados):
                tabela_mapeamento.append([str(ip_ind_pub), f"{p_start} à {p_end}", str(ip_ind_priv)])

    # --- PDF ---
    pdf = RelatorioCGNAT()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Texto inicial ético [cite: 97]
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(0, 5, "O motivo de ser tudo impresso na tela não tendo opções para download é que todos os dados preenchidos nunca serão armazenados. Ética!", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    pdf.set_font("Courier", size=6)
    largura_util = pdf.epw
    for linha in script_saida:
        pdf.multi_cell(largura_util, 3.5, linha, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    # Tabela de Mapeamento Individual [cite: 3, 4]
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "MAPEAMENTO DAS PORTAS", align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(5)

    # Cabeçalho da Tabela
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(60, 7, "IP Público", border=1, fill=True, align='C')
    pdf.cell(70, 7, "Range de Portas", border=1, fill=True, align='C')
    pdf.cell(60, 7, "IP Privado", border=1, fill=True, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Dados Sequenciais (IP por IP)
    pdf.set_font("Helvetica", size=8)
    for row in tabela_mapeamento:
        pdf.cell(60, 6, row[0], border=1, align='C')
        pdf.cell(70, 6, row[1], border=1, align='C')
        pdf.cell(60, 6, row[2], border=1, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output("CGNAT_MAPEAMENTO_SEQUENCIAL.pdf")
    print(f"\n[SUCESSO] Gerado relatório com {len(tabela_mapeamento)} IPs individuais.")

if __name__ == "__main__":
    gerar_cgnat_final()