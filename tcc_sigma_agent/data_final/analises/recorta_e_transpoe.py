"""
recorta_e_transpoe.py

Lê um arquivo CSV, recorta um intervalo de linhas e transpõe (linhas viram colunas).
Salva o resultado em um novo arquivo CSV.

Uso típico:
    python recorta_e_transpoe.py entrada.csv saida.csv --inicio 10 --fim 25
"""

import argparse
import pandas as pd
from pathlib import Path


def recortar_e_transpor(
    caminho_entrada: Path,
    caminho_saida: Path,
    linha_inicio: int,
    linha_fim: int,
    separador: str = ",",
    tem_cabecalho: bool = True,
    manter_cabecalho_no_resultado: bool = True,
) -> None:
    """
    Recorta um intervalo de linhas de um CSV e transpõe o resultado.

    Parâmetros:
        caminho_entrada: caminho do arquivo CSV de origem.
        caminho_saida: caminho do arquivo CSV que será criado.
        linha_inicio: número da primeira linha a incluir (começando em 1,
            ignorando a linha de cabeçalho).
        linha_fim: número da última linha a incluir (inclusivo).
        separador: caractere separador do CSV (vírgula por padrão).
        tem_cabecalho: True se a primeira linha do CSV contém os nomes
            das colunas.
        manter_cabecalho_no_resultado: True para preservar os nomes das
            colunas como primeira coluna no arquivo transposto.
    """
    # 1. Leitura do arquivo.
    #    O parâmetro `header=0` diz que a linha 0 é cabeçalho; `None` indica
    #    que não há cabeçalho e as colunas receberão nomes automáticos.
    df = pd.read_csv(
        caminho_entrada,
        sep=separador,
        header=0 if tem_cabecalho else None,
    )

    print(f"Arquivo lido: {len(df)} linhas, {len(df.columns)} colunas.")

    # 2. Validação do intervalo.
    #    Convertendo de "humano" (1-indexado) para "Python" (0-indexado):
    #    a linha 1 do usuário é o índice 0 do pandas.
    if linha_inicio < 1:
        raise ValueError("linha_inicio deve ser >= 1.")
    if linha_fim > len(df):
        raise ValueError(
            f"linha_fim ({linha_fim}) é maior que o total de linhas ({len(df)})."
        )
    if linha_inicio > linha_fim:
        raise ValueError("linha_inicio deve ser <= linha_fim.")

    # 3. Recorte.
    #    .iloc[a:b] no pandas pega da posição `a` até `b-1` (exclusivo no fim),
    #    então somamos 1 ao `linha_fim` para incluir a última linha pedida.
    recorte = df.iloc[linha_inicio - 1 : linha_fim]
    print(f"Recortadas {len(recorte)} linhas (de {linha_inicio} a {linha_fim}).")

    # 4. Transposição.
    #    O método .T do pandas é o atalho para transpor: linhas viram colunas.
    transposto = recorte.T

    # 5. Tratamento do cabeçalho no resultado.
    #    Após transpor, o que eram nomes de colunas vira a primeira coluna
    #    (o "índice"). Por padrão, vamos preservá-lo como uma coluna comum
    #    para que apareça no CSV de saída.
    if manter_cabecalho_no_resultado:
        transposto = transposto.reset_index()
        # Renomeia a coluna que veio do índice para algo descritivo.
        transposto = transposto.rename(columns={"index": "campo"})

    # 6. Salvar.
    #    `index=False` evita que o pandas escreva uma coluna extra
    #    com a numeração das linhas.
    transposto.to_csv(caminho_saida, sep=separador, index=False)
    print(f"Arquivo salvo em: {caminho_saida}")
    print(f"Resultado: {len(transposto)} linhas, {len(transposto.columns)} colunas.")


def main():
    parser = argparse.ArgumentParser(
        description="Recorta um intervalo de linhas de um CSV e transpõe o resultado."
    )
    parser.add_argument("entrada", type=Path, help="Caminho do CSV de entrada.")
    parser.add_argument("saida", type=Path, help="Caminho do CSV de saída.")
    parser.add_argument(
        "--inicio",
        type=int,
        required=True,
        help="Número da primeira linha a incluir (1-indexado, sem contar o cabeçalho).",
    )
    parser.add_argument(
        "--fim",
        type=int,
        required=True,
        help="Número da última linha a incluir (inclusivo).",
    )
    parser.add_argument(
        "--sep",
        type=str,
        default=",",
        help="Separador do CSV (padrão: vírgula).",
    )
    parser.add_argument(
        "--sem-cabecalho",
        action="store_true",
        help="Use se o arquivo NÃO tem linha de cabeçalho.",
    )

    args = parser.parse_args()

    recortar_e_transpor(
        caminho_entrada=args.entrada,
        caminho_saida=args.saida,
        linha_inicio=args.inicio,
        linha_fim=args.fim,
        separador=args.sep,
        tem_cabecalho=not args.sem_cabecalho,
    )


if __name__ == "__main__":
    main()