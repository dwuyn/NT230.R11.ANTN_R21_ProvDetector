"""PV-DM doc2vec embeddings for causal-path sentences."""
from __future__ import annotations

from collections.abc import Iterable, Sequence

import numpy as np
from gensim.models.doc2vec import Doc2Vec, TaggedDocument


class PathEncoder:
    def __init__(
        self,
        vector_size: int = 100,
        dm: int = 1,
        window: int = 3,
        epochs: int = 100,
        seed: int = 20261025,
    ):
        self.vector_size = vector_size
        self.dm = dm
        self.window = window
        self.epochs = epochs
        self.seed = seed
        self.model: Doc2Vec | None = None

    def fit(self, sentences: Sequence[Sequence[str]]) -> PathEncoder:
        if len(sentences) < 2:
            raise ValueError("doc2vec needs at least two training paths")
        documents = [TaggedDocument(list(tokens), [index]) for index, tokens in enumerate(sentences)]
        model = Doc2Vec(
            vector_size=self.vector_size,
            dm=self.dm,
            window=self.window,
            min_count=1,
            epochs=self.epochs,
            workers=1,
            seed=self.seed,
            sample=0,
            negative=5,
            hs=0,
        )
        model.build_vocab(documents)
        model.train(documents, total_examples=model.corpus_count, epochs=model.epochs)
        self.model = model
        return self

    def transform(self, sentences: Sequence[Sequence[str]]) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("encoder is not fitted")
        vectors = []
        for tokens in sentences:
            self.model.random.seed(self.seed)
            vectors.append(self.model.infer_vector(list(tokens), epochs=self.epochs, alpha=0.025))
        if not vectors:
            return np.zeros((0, self.vector_size), dtype=np.float64)
        return np.asarray(vectors, dtype=np.float64)

    def save(self, path: str) -> None:
        if self.model is None:
            raise RuntimeError("encoder is not fitted")
        self.model.save(path)

    @classmethod
    def load(cls, path: str) -> PathEncoder:
        model = Doc2Vec.load(path)
        encoder = cls(vector_size=model.vector_size, dm=model.dm, window=model.window)
        encoder.model = model
        return encoder


def sentences(paths_by_instance: dict[int, Iterable]) -> list[list[str]]:
    return [list(path.tokens) for paths in paths_by_instance.values() for path in paths]
