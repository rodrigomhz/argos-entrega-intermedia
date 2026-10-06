import argparse

from argos import __version__


def main():
    parser = argparse.ArgumentParser(prog="argos", description="Analizador local de ficheros sospechosos")
    parser.add_argument("--version", action="version", version=f"argos {__version__}")
    parser.parse_args()


if __name__ == "__main__":
    main()
