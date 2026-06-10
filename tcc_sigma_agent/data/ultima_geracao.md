daniela@Dani-PC1:~/Documents/TCC/tcc_sigma_agent/src$ python3 gerador_datasets_unificado_segunda_versao.py 
============================================================
PASSO 1: Lendo o repositório Sigma...
============================================================
 -> 3748 regras válidas encontradas no repositório.

============================================================
PASSO 2: Normalizando nomes dos arquivos em test_cases...
============================================================
 -> Construindo mapa de IDs do repositório...
 -> 3748 regras com UUID mapeadas.
 -> Já corretos: 50 | Renomeados: 0 | Não encontrados: 0

============================================================
PASSO 3: Mapeando test_cases → repositório...
============================================================
 -> 50 arquivos em test_cases.
 -> 50 localizados no repositório atual.

============================================================
PASSO 4: Construindo pool disponível...
============================================================
 -> 3698 regras disponíveis
    (3748 total − 50 já no test_cases)
 -> 128 categorias distintas no pool.

============================================================
PASSO 5: Adicionando 0 nova(s) regra(s) ao test_cases...
============================================================
 -> test_cases agora tem 50 regras.

============================================================
PASSO 6: Selecionando 10 regras para extra_test_cases (round-robin)...
============================================================
 -> 10 regras extras selecionadas.

============================================================
PASSO 7: Selecionando 75% do pool para rag_knowledge...
============================================================
 -> Meta: 2773 regras (75% de 3698)
 -> 2773 regras selecionadas para rag_knowledge.

============================================================
PASSO 8: Gravando arquivos em disco...
============================================================
 -> rag_knowledge antiga removida.

============================================================
PASSO 9: Relatório de distribuição (auditoria de viés)
============================================================

--- Distribuição de 'REPOSITÓRIO COMPLETO' (3748 regras) ---
   Categorias distintas representadas: 138
   Top 10 categorias mais frequentes:
      1409  ( 37.6%)  ██████████████████ process_creation_windows_any
       224  (  6.0%)  ██ registry_set_windows_any
       218  (  5.8%)  ██ file_event_windows_any
       178  (  4.7%)  ██ ps_script_windows_any
       170  (  4.5%)  ██ any_windows_security
       141  (  3.8%)  █ process_creation_linux_any
       123  (  3.3%)  █ image_load_windows_any
        82  (  2.2%)  █ webserver_any_any
        74  (  2.0%)   any_windows_system
        70  (  1.9%)   process_creation_macos_any

--- Distribuição de 'rag_knowledge' (2773 regras) ---
   Categorias distintas representadas: 124
   Top 10 categorias mais frequentes:
       493  ( 17.8%)  ████████ process_creation_windows_any
       223  (  8.0%)  ████ registry_set_windows_any
       216  (  7.8%)  ███ file_event_windows_any
       177  (  6.4%)  ███ ps_script_windows_any
       168  (  6.1%)  ███ any_windows_security
       140  (  5.0%)  ██ process_creation_linux_any
       122  (  4.4%)  ██ image_load_windows_any
        81  (  2.9%)  █ webserver_any_any
        74  (  2.7%)  █ any_windows_system
        69  (  2.5%)  █ process_creation_macos_any

--- Distribuição de 'extra_test_cases' (10 regras) ---
   Categorias distintas representadas: 10
   Top 10 categorias mais frequentes:
         1  ( 10.0%)  █████ any_cisco_aaa
         1  ( 10.0%)  █████ any_linux_sshd
         1  ( 10.0%)  █████ any_windows_dns-client
         1  ( 10.0%)  █████ any_linux_auth
         1  ( 10.0%)  █████ any_windows_printservice-admin
         1  ( 10.0%)  █████ any_windows_driver-framework
         1  ( 10.0%)  █████ any_windows_security
         1  ( 10.0%)  █████ any_windows_taskscheduler
         1  ( 10.0%)  █████ proxy_any_any
         1  ( 10.0%)  █████ any_any_nginx

============================================================
CONCLUÍDO — Resumo dos datasets
============================================================
  test_cases       (PRESERVADA + 0 nova):  50 regras
  rag_knowledge    (RECRIADA):                          2773 regras
  extra_test_cases (RECRIADA):                          10 regras
  Total distribuído: 2833 de 3748 regras do repositório
============================================================

