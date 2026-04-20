import os
import json
import random
import math

# Configuration
SOURCE_DIR = "attack_datasets"
OUTPUT_DIR = "dataset_splits"
TRAIN_RATIO = 0.7
TEST_RATIO = 0.2
VAL_RATIO = 0.1


def split_dataset():
    # Create output directories
    for split_name in ["training", "test", "validation"]:
        os.makedirs(os.path.join(OUTPUT_DIR, split_name), exist_ok=True)

    # Process each scenario file
    files = [f for f in os.listdir(SOURCE_DIR) if f.endswith(".json")]
    print(f"Found {len(files)} files to process.")

    for filename in files:
        source_path = os.path.join(SOURCE_DIR, filename)

        with open(source_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        attacks = data.get("attacks", [])
        total_attacks = len(attacks)

        # Shuffle attacks ensuring randomness
        random.seed(42)  # Fixed seed for reproducibility
        random.shuffle(attacks)

        # Calculate split indices
        train_count = math.ceil(total_attacks * TRAIN_RATIO)
        test_count = math.floor(total_attacks * TEST_RATIO)
        # Validation gets the remainder

        train_data = attacks[:train_count]
        test_data = attacks[train_count : train_count + test_count]
        val_data = attacks[train_count + test_count :]

        # Create split objects maintaining original metadata structure
        def create_split_json(split_attacks):
            new_data = data.copy()
            new_data["attacks"] = split_attacks
            return new_data

        splits = {
            "training": create_split_json(train_data),
            "test": create_split_json(test_data),
            "validation": create_split_json(val_data),
        }

        # Save files
        for split_name, split_content in splits.items():
            output_path = os.path.join(OUTPUT_DIR, split_name, filename)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(split_content, f, indent=2, ensure_ascii=False)

        print(
            f"Processed {filename}: Total={total_attacks} -> Train={len(train_data)}, Test={len(test_data)}, Val={len(val_data)}"
        )


if __name__ == "__main__":
    split_dataset()
