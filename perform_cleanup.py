import os
import shutil

TARGET_DIR = r"C:\Users\Logix\dev\apitest"
BACKUP_DIR = os.path.join(TARGET_DIR, "legacy_backup")

FILES_TO_MOVE = [
    "gui.py",
    "app.py",
    "test_pii.py",
    "test_ui.py",
    "test_input.csv",
    "patcher.py",
    "plan_analysis_polish.md",
    "CLEANUP.bat"
]

def cleanup():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        print(f"Created {BACKUP_DIR}")

    for file in FILES_TO_MOVE:
        src = os.path.join(TARGET_DIR, file)
        dst = os.path.join(BACKUP_DIR, file)
        
        if os.path.exists(src):
            try:
                shutil.move(src, dst)
                print(f"Moved {file} to backup.")
            except Exception as e:
                print(f"Failed to move {file}: {e}")
        else:
            print(f"Skipped {file} (Not found)")

if __name__ == "__main__":
    cleanup()
