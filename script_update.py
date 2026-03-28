import requests
import os
import json
from m3u_processor import M3UProcessor
import time

class IPTVUpdater:
    def __init__(self):
        self.pasta_downloads = "downloads"
        self.pasta_output = "docs"
        self.api_url = "https://api.github.com/repos/josieljefferson/iptv-panel/contents/"
        self.ignorar = ["requirements.txt", ".gitignore", "README.md"]
        
        # Criar pastas
        os.makedirs(self.pasta_downloads, exist_ok=True)
        os.makedirs(self.pasta_output, exist_ok=True)
    
    def listar_arquivos(self):
        """Lista arquivos M3U do repositório"""
        try:
            print("📡 Listando arquivos do repositório...")
            response = requests.get(self.api_url, timeout=10)
            response.raise_for_status()
            
            arquivos = []
            for item in response.json():
                nome = item["name"]
                
                # Ignorar arquivos específicos
                if nome in self.ignorar:
                    continue
                
                # Aceitar listas IPTV
                if nome.endswith((".m3u", ".m3u8", ".txt")):
                    arquivos.append(item["download_url"])
                    print(f"  ✅ Encontrado: {nome}")
            
            print(f"📊 Total de arquivos: {len(arquivos)}")
            return arquivos
        except Exception as e:
            print(f"❌ Erro ao listar arquivos: {e}")
            return []
    
    def baixar_arquivo(self, url):
        """Baixa um arquivo individual"""
        nome = url.split("/")[-1].split("?")[0]
        caminho = os.path.join(self.pasta_downloads, nome)
        
        try:
            print(f"⬇️  Baixando: {nome}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            with open(caminho, "wb") as f:
                f.write(response.content)
            
            return True
        except Exception as e:
            print(f"❌ Erro ao baixar {nome}: {e}")
            return False
    
    def baixar_arquivos(self, urls):
        """Baixa todos os arquivos"""
        sucessos = 0
        for url in urls:
            if self.baixar_arquivo(url):
                sucessos += 1
            time.sleep(0.5)  # Delay para evitar bloqueio
        
        print(f"✅ Baixados: {sucessos}/{len(urls)} arquivos")
        return sucessos > 0
    
    def processar_playlist(self):
        """Processa a playlist e gera o arquivo final"""
        print("🔄 Processando playlists...")
        processor = M3UProcessor()
        canais = processor.processar_lista(self.pasta_downloads, self.pasta_output)
        
        print(f"📺 Total de canais processados: {len(canais)}")
        return canais
    
    def salvar_json(self, canais):
        """Salva a playlist em formato JSON"""
        try:
            caminho = os.path.join(self.pasta_output, "playlists.json")
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump({
                    "total": len(canais),
                    "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "channels": canais
                }, f, indent=2, ensure_ascii=False)
            print(f"💾 JSON salvo: {caminho}")
        except Exception as e:
            print(f"❌ Erro ao salvar JSON: {e}")
    
    def gerar_estatisticas(self, canais):
        """Gera estatísticas da playlist"""
        grupos = {}
        for canal in canais:
            grupo = canal.get("group", "OUTROS")
            grupos[grupo] = grupos.get(grupo, 0) + 1
        
        stats = {
            "total_canais": len(canais),
            "grupos": grupos,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        caminho = os.path.join(self.pasta_output, "stats.json")
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        
        print("\n📊 Estatísticas:")
        print(f"  Total de canais: {stats['total_canais']}")
        print(f"  Grupos disponíveis: {len(grupos)}")
        
        return stats
    
    def run(self):
        """Executa o fluxo completo"""
        print("🚀 Iniciando atualização do IPTV System...\n")
        
        # 1. Listar arquivos
        arquivos = self.listar_arquivos()
        if not arquivos:
            print("❌ Nenhum arquivo encontrado para processar")
            return False
        
        # 2. Baixar arquivos
        if not self.baixar_arquivos(arquivos):
            print("⚠️  Alguns arquivos não puderam ser baixados")
        
        # 3. Processar playlist
        canais = self.processar_playlist()
        
        # 4. Salvar JSON
        self.salvar_json(canais)
        
        # 5. Gerar estatísticas
        self.gerar_estatisticas(canais)
        
        print("\n✅ Atualização concluída com sucesso!")
        return True

if __name__ == "__main__":
    updater = IPTVUpdater()
    updater.run()