from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcp_firewall.gliner2_dataset import export_gliner2_splits, ensure_hf_style_source


def _require_gliner2_dependencies() -> tuple[object, object, object]:
    try:
        import torch
        from gliner2 import GLiNER2
        from gliner2.training.trainer import GLiNER2Trainer, TrainingConfig
    except ImportError as exc:
        raise RuntimeError(
            "GLiNER2 LoRA training requires the `gliner2` extra plus `peft`. Install the GLiNER2 dependencies first."
        ) from exc
    return torch, GLiNER2, GLiNER2Trainer, TrainingConfig


def ensure_gliner2_data(hf_source_dir: Path, gliner2_data_dir: Path) -> dict[str, Path]:
    existing = {
        split_name: gliner2_data_dir / f"{split_name}.jsonl"
        for split_name in ("train", "validation", "test")
    }
    if all(path.exists() for path in existing.values()):
        return existing

    ensure_hf_style_source(hf_source_dir)
    return export_gliner2_splits(hf_source_dir, gliner2_data_dir)


def write_training_manifest(output_dir: Path, *, base_model: str, gliner2_data_dir: Path) -> Path:
    manifest = {
        "base_model": base_model,
        "data_dir": str(gliner2_data_dir),
        "recommended_runtime_checkpoint": str(output_dir / "best"),
        "fallback_runtime_checkpoint": str(output_dir / "final"),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "training_manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def train(
    *,
    base_model: str,
    train_data: Path,
    validation_data: Path,
    output_dir: Path,
    resume_from_checkpoint: Path | None,
    epochs: int,
    batch_size: int,
    eval_batch_size: int,
    gradient_accumulation_steps: int,
    encoder_lr: float,
    task_lr: float,
    lora_r: int,
    lora_alpha: float,
    lora_dropout: float,
    lora_target_modules: list[str],
    save_adapter_only: bool,
    max_len: int | None,
) -> Path:
    torch, GLiNER2, GLiNER2Trainer, TrainingConfig = _require_gliner2_dependencies()

    model = GLiNER2.from_pretrained(base_model)
    config = TrainingConfig(
        output_dir=str(output_dir),
        num_epochs=epochs,
        batch_size=batch_size,
        eval_batch_size=eval_batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        encoder_lr=encoder_lr,
        task_lr=task_lr,
        eval_strategy="epoch",
        save_best=True,
        fp16=False,
        bf16=False,
        num_workers=0,
        pin_memory=False,
        use_lora=True,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        lora_target_modules=lora_target_modules,
        save_adapter_only=save_adapter_only,
        max_len=max_len,
    )

    trainer = GLiNER2Trainer(model, config)
    if torch.cuda.is_available():
        pass
    elif torch.backends.mps.is_available():
        trainer.device = torch.device("mps")
        trainer.model.to(trainer.device)

    if resume_from_checkpoint is not None:
        trainer.load_checkpoint(str(resume_from_checkpoint))
        if hasattr(trainer.model, "peft_config"):
            for peft_cfg in trainer.model.peft_config.values():
                peft_cfg.inference_mode = False
        for name, parameter in trainer.model.named_parameters():
            if "lora_" in name:
                parameter.requires_grad = True
        trainer.model.train()

    trainer.train(train_data=str(train_data), eval_data=str(validation_data))
    return output_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a GLiNER2 LoRA adapter for suspicious MCP request spans.")
    parser.add_argument(
        "--hf-source-dir",
        type=Path,
        default=Path("data/mcp_suspicious_requests_hf_v5_span_curated"),
        help="HF-style dataset directory with train/validation/test JSON files.",
    )
    parser.add_argument(
        "--gliner2-data-dir",
        type=Path,
        default=Path("data/mcp_suspicious_requests_gliner2_v5_span_curated"),
        help="Directory with GLiNER2 JSONL splits.",
    )
    parser.add_argument(
        "--base-model",
        default="fastino/gliner2-large-v1",
        help="Base GLiNER2 checkpoint to adapt.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/gliner2_mcp_adapter_v5_span_curated_cpu_e3_bs8_ml64_safe1"),
        help="Directory where the LoRA adapter training outputs will be saved.",
    )
    parser.add_argument(
        "--resume-from-checkpoint",
        type=Path,
        default=None,
        help="Optional adapter checkpoint directory to continue training from.",
    )
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--eval-batch-size", type=int, default=1)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=8)
    parser.add_argument("--encoder-lr", type=float, default=1e-5)
    parser.add_argument("--task-lr", type=float, default=5e-4)
    parser.add_argument("--lora-r", type=int, default=4)
    parser.add_argument("--lora-alpha", type=float, default=8.0)
    parser.add_argument("--lora-dropout", type=float, default=0.0)
    parser.add_argument("--max-len", type=int, default=128)
    parser.add_argument(
        "--lora-target-modules",
        default="encoder,span_rep,classifier,count_embed,count_pred",
        help="Comma-separated GLiNER2 module groups to adapt with LoRA.",
    )
    parser.add_argument(
        "--save-full-model",
        action="store_true",
        help="Save the full fine-tuned checkpoint instead of adapter-only weights.",
    )
    args = parser.parse_args()

    paths = ensure_gliner2_data(args.hf_source_dir, args.gliner2_data_dir)
    manifest_path = write_training_manifest(
        args.output_dir,
        base_model=args.base_model,
        gliner2_data_dir=args.gliner2_data_dir,
    )
    lora_target_modules = [
        module_name.strip()
        for module_name in args.lora_target_modules.split(",")
        if module_name.strip()
    ]
    train(
        base_model=args.base_model,
        train_data=paths["train"],
        validation_data=paths["validation"],
        output_dir=args.output_dir,
        resume_from_checkpoint=args.resume_from_checkpoint,
        epochs=args.epochs,
        batch_size=args.batch_size,
        eval_batch_size=args.eval_batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        encoder_lr=args.encoder_lr,
        task_lr=args.task_lr,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        lora_target_modules=lora_target_modules,
        save_adapter_only=not args.save_full_model,
        max_len=args.max_len,
    )
    print(f"GLiNER2 LoRA training outputs: {args.output_dir}")
    print(f"recommended_runtime_checkpoint: {args.output_dir / 'best'}")
    print(f"fallback_runtime_checkpoint: {args.output_dir / 'final'}")
    print(f"training_manifest: {manifest_path}")


if __name__ == "__main__":
    main()
