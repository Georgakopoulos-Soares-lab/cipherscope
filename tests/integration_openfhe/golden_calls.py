"""Stable, manually inspectable source sites for real-binding trace assertions."""

from __future__ import annotations

from typing import Any


def eval_add_site(context: Any, left: Any, right: Any) -> Any:
    return context.EvalAdd(left, right)


def eval_mult_site(context: Any, left: Any, right: Any) -> Any:
    return context.EvalMult(left, right)


def eval_rotate_site(context: Any, ciphertext: Any, index: int) -> Any:
    return context.EvalRotate(ciphertext, index)


def eval_bootstrap_site(context: Any, ciphertext: Any) -> Any:
    return context.EvalBootstrap(ciphertext)


def encrypt_site(context: Any, public_key: Any, plaintext: Any) -> Any:
    return context.Encrypt(public_key, plaintext)


def decrypt_site(context: Any, ciphertext: Any, private_key: Any) -> Any:
    return context.Decrypt(ciphertext, private_key)
