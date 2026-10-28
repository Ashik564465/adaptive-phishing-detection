from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer


@dataclass(frozen=True)
class EmbeddingConfig:
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    max_length: int = 256


class HuggingFaceEmbedder:
    """
    Generate semantic embeddings using a Hugging Face
    Transformer model.

    The embedding model is separate from the primary
    phishing classifier.
    """

    def __init__(
        self,
        config: EmbeddingConfig | None = None,
        device: str | None = None,
    ):
        self.config = config or EmbeddingConfig()

        if device is None:
            device = (
                "cuda"
                if torch.cuda.is_available()
                else "cpu"
            )

        self.device = torch.device(device)

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.config.model_name
        )

        self.model = AutoModel.from_pretrained(
            self.config.model_name
        )

        self.model.to(self.device)
        self.model.eval()

        # all-MiniLM-L6-v2 produces 384-dimensional embeddings.
        self.embedding_dimension = (
            self.model.config.hidden_size
        )

    @staticmethod
    def _mean_pooling(
        model_output,
        attention_mask: torch.Tensor,
    ) -> torch.Tensor:
        """
        Mean-pool token embeddings while ignoring padding.
        """

        token_embeddings = model_output.last_hidden_state

        mask = attention_mask.unsqueeze(-1).expand(
            token_embeddings.size()
        ).float()

        summed = torch.sum(
            token_embeddings * mask,
            dim=1,
        )

        counts = torch.clamp(
            mask.sum(dim=1),
            min=1e-9,
        )

        return summed / counts

    def encode(
        self,
        texts: str | list[str],
        batch_size: int = 4,
    ) -> np.ndarray:
        """
        Generate normalized sentence embeddings.

        Parameters
        ----------
        texts:
            Either one string or a list of strings.

        batch_size:
            Number of texts processed at a time.

        Returns
        -------
        numpy.ndarray

        For a single string:
            shape = (embedding_dimension,)

        For a list of strings:
            shape = (N, embedding_dimension)
        """

        if batch_size <= 0:
            raise ValueError(
                "batch_size must be greater than zero."
            )

        # Preserve the original convenient API:
        # one string -> one vector.
        single_input = isinstance(texts, str)

        if single_input:
            text_list = [texts]
        else:
            text_list = list(texts)

        # Empty input.
        if not text_list:
            return np.empty(
                (
                    0,
                    self.embedding_dimension,
                ),
                dtype=np.float32,
            )

        all_embeddings: list[np.ndarray] = []

        for start in range(
            0,
            len(text_list),
            batch_size,
        ):
            batch_texts = text_list[
                start:start + batch_size
            ]

            encoded = self.tokenizer(
                batch_texts,
                padding=True,
                truncation=True,
                max_length=self.config.max_length,
                return_tensors="pt",
            )

            encoded = {
                key: value.to(self.device)
                for key, value in encoded.items()
            }

            with torch.no_grad():
                outputs = self.model(**encoded)

                embeddings = self._mean_pooling(
                    outputs,
                    encoded["attention_mask"],
                )

                embeddings = torch.nn.functional.normalize(
                    embeddings,
                    p=2,
                    dim=1,
                )

            batch_result = (
                embeddings
                .detach()
                .cpu()
                .numpy()
                .astype(np.float32)
            )

            all_embeddings.append(batch_result)

            # Release GPU memory after every batch.
            del encoded
            del outputs
            del embeddings

            if self.device.type == "cuda":
                torch.cuda.empty_cache()

        result = np.vstack(
            all_embeddings
        )

        # Single string -> 1D vector.
        if single_input:
            return result[0]

        # Multiple strings -> 2D matrix.
        return result