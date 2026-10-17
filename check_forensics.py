
import inspect
import forensics


def main():
    print("=" * 55)
    print("DataLens - Forensics Module Diagnostic")
    print("=" * 55)

    # 1. Confirm which forensics.py Python imported
    print("\n[1] Loaded module file:")
    print(forensics.__file__)

    # 2. Locate inspect_evidence()
    print("\n[2] inspect_evidence() function location:")
    function = getattr(forensics, "inspect_evidence", None)

    if callable(function):
        print(inspect.getsourcefile(function))
    else:
        print("ERROR: inspect_evidence() was not found.")

    # 3. Check TEXT_EXTENSIONS
    print("\n[3] File extension check:")
    extensions = getattr(forensics, "TEXT_EXTENSIONS", None)

    if extensions is None:
        print("ERROR: TEXT_EXTENSIONS was not found.")
    else:
        print(".doc in TEXT_EXTENSIONS:", ".doc" in extensions)
        print(".docx in TEXT_EXTENSIONS:", ".docx" in extensions)
        print(".txt in TEXT_EXTENSIONS:", ".txt" in extensions)
        print(".pdf in TEXT_EXTENSIONS:", ".pdf" in extensions)

    print("\nDiagnostic completed.")


if __name__ == "__main__":
    main()
