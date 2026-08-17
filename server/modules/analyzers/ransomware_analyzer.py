# modules/analyzers/ransomware_analyzer.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from database import SessionLocal, ModuleData
from .base_analyzer import BaseAnalyzer
import re

class RansomwareAnalyzer(BaseAnalyzer):
    """
    Analizador para el módulo ransomware_shield.
    Detecta anomalías en las ráfagas de cambios de archivos.
    """

    def _collect_data(self) -> list:
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(days=self.window_days)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'ransomware_shield',
                ModuleData.timestamp >= since
            ).order_by(ModuleData.timestamp).all()
            return data
        finally:
            db.close()

    def _extract_features(self, events):
        if not events:
            return pd.DataFrame()

        rows = []
        for e in events:
            d = e.data
            # Solo nos interesan los eventos de cambio de archivo
            if d.get('event') == 'file_change':
                rows.append({
                    'timestamp': e.timestamp,
                    'path': d.get('path'),
                    'process': d.get('process', 'unknown')
                })

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        # Agrupar por minuto en lugar de hora
        df['interval'] = df['timestamp'].dt.floor('min')
        grouped = df.groupby('interval')

        # Características base
        total_changes = grouped.size().rename('total_changes')
        # Número de procesos distintos por minuto
        unique_processes = grouped['process'].apply(lambda x: x[x != ''].nunique()).rename('unique_processes') if 'process' in df else pd.Series(0, index=grouped.indices).rename('unique_processes')

        # Ya no usamos características de hora del día
        features = pd.concat([
            total_changes,
            unique_processes
        ], axis=1).fillna(0)

        return features

    def _train_model(self, features):
        model = IsolationForest(contamination=self.config.get('contamination', 0.01), random_state=42)
        model.fit(features)
        return model, features.columns.tolist()

    def _detect_anomalies(self):
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(seconds=self.detection_interval)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'ransomware_shield',
                ModuleData.timestamp >= since
            ).all()
            if len(data) < 5:
                return []
            df = self._extract_features(data)
            if df.empty:
                return []
            # Asegurar columnas
            for col in self.feature_names:
                if col not in df.columns:
                    df[col] = 0
            df = df[self.feature_names]
            preds = self.model.predict(df)
            anomalies = []
            for idx, (pred, (index, row)) in enumerate(zip(preds, df.iterrows())):
                if pred == -1:
                    interval = index
                    anomalies.append({
                        'module': 'ransomware_shield',
                        'timestamp': interval.isoformat() if hasattr(interval, 'isoformat') else str(interval),
                        'features': row.to_dict()
                    })
            return anomalies
        finally:
            db.close()