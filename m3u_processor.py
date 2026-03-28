import os
import re
import requests
import json
from urllib.parse import urlparse

# Regex para extrair atributos
regex_attr = re.compile(r'([\w-]+)="([^"]*)"')

# EPG URLs otimizadas
EPG_URLS = [
    "https://m3u4u.com/epg/jq2zy9epr3bwxmgwyxr5",
    "https://m3u4u.com/epg/3wk1y24kx7uzdevxygz7",
    "https://m3u4u.com/epg/782dyqdrqkh1xegen4zp",
    "https://www.open-epg.com/files/brazil1.xml.gz",
    "https://www.open-epg.com/files/brazil2.xml.gz",
    "https://www.open-epg.com/files/brazil3.xml.gz",
    "https://www.open-epg.com/files/brazil4.xml.gz",
    "https://www.open-epg.com/files/portugal1.xml.gz",
    "https://www.open-epg.com/files/portugal2.xml.gz",
    "https://epgshare01.online/epgshare01/epg_ripper_BR1.xml.gz",
    "https://epgshare01.online/epgshare01/epg_ripper_PT1.xml.gz"
]

class M3UProcessor:
    def __init__(self):
        self.canais = []
        self.urls_vistas = set()
    
    def extrair_atributos(self, linha):
        """Extrai atributos da linha EXTINF"""
        attrs = dict(regex_attr.findall(linha))
        return {
            "tvg_id": attrs.get("tvg-id", ""),
            "tvg_name": attrs.get("tvg-name", ""),
            "tvg_logo": attrs.get("tvg-logo", ""),
            "group": attrs.get("group-title", "OUTROS")
        }
    
    def extrair_nome(self, linha):
        """Extrai o nome do canal"""
        return linha.split(",")[-1].strip() if "," in linha else "Sem Nome"
    
    def limpar_texto(self, txt):
        return txt.strip() if txt else ""
    
    def processar_arquivo(self, caminho):
        """Processa um único arquivo M3U"""
        try:
            with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
                dados_extinf = None
                
                for linha in f:
                    linha = linha.strip()
                    if not linha:
                        continue
                    
                    if linha.startswith("#EXTINF"):
                        attrs = self.extrair_atributos(linha)
                        nome = self.extrair_nome(linha)
                        
                        dados_extinf = {
                            "nome": self.limpar_texto(nome) or "Sem Nome",
                            "tvg_id": self.limpar_texto(attrs["tvg_id"]),
                            "tvg_name": self.limpar_texto(attrs["tvg_name"]) or nome,
                            "tvg_logo": self.limpar_texto(attrs["tvg_logo"]),
                            "group": self.limpar_texto(attrs["group"]) or "OUTROS"
                        }
                    
                    elif linha.startswith("http"):
                        if linha not in self.urls_vistas:
                            self.urls_vistas.add(linha)
                            
                            canal = dados_extinf.copy() if dados_extinf else {
                                "nome": "Sem Nome",
                                "tvg_id": "",
                                "tvg_name": "Sem Nome",
                                "tvg_logo": "",
                                "group": "OUTROS"
                            }
                            
                            canal["url"] = linha
                            self.canais.append(canal)
                            
                            dados_extinf = None
        except Exception as e:
            print(f"Erro ao processar {caminho}: {e}")
    
    def gerar_playlist(self, pasta_saida):
        """Gera a playlist final com header profissional"""
        # Header da playlist
        epg_string = ",".join(EPG_URLS)
        
        header = (
            f'#EXTM3U url-tvg="{epg_string}"\n\n'
            '#PLAYLISTV: '
            'pltv-logo="https://cdn-icons-png.flaticon.com/256/25/25231.png" '
            'pltv-name="IPTV System" '
            'pltv-description="Playlist IPTV Automática" '
            'pltv-cover="https://images.icon-icons.com/2407/PNG/512/gitlab_icon_146171.png" '
            'pltv-author="IPTV System" '
            'pltv-site="https://github.com/josieljefferson/iptv-panel" '
            'pltv-email="suporte@iptvsystem.com"\n\n'
        )
        
        # Salvar playlist
        caminho_saida = os.path.join(pasta_saida, "playlists.m3u")
        
        with open(caminho_saida, "w", encoding="utf-8") as f:
            f.write(header)
            
            for c in self.canais:
                # Escapar caracteres especiais nos atributos
                tvg_id = c["tvg_id"].replace('"', '&quot;')
                tvg_name = c["tvg_name"].replace('"', '&quot;')
                tvg_logo = c["tvg_logo"].replace('"', '&quot;')
                group = c["group"].replace('"', '&quot;')
                nome = c["nome"].replace('"', '&quot;')
                
                f.write(
                    f'#EXTINF:-1 tvg-id="{tvg_id}" '
                    f'tvg-name="{tvg_name}" '
                    f'tvg-logo="{tvg_logo}" '
                    f'group-title="{group}",{nome}\n'
                )
                f.write(c["url"] + "\n\n")
        
        return self.canais
    
    def processar_lista(self, pasta_entrada, pasta_saida):
        """Processa todos os arquivos M3U na pasta de entrada"""
        for arquivo in os.listdir(pasta_entrada):
            if arquivo.endswith((".m3u", ".m3u8", ".txt")):
                caminho = os.path.join(pasta_entrada, arquivo)
                print(f"Processando: {arquivo}")
                self.processar_arquivo(caminho)
        
        # Remover duplicatas baseado na URL
        urls_vistas = set()
        canais_unicos = []
        
        for canal in self.canais:
            if canal["url"] not in urls_vistas:
                urls_vistas.add(canal["url"])
                canais_unicos.append(canal)
        
        self.canais = canais_unicos
        return self.gerar_playlist(pasta_saida)