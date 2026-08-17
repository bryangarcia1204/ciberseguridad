# modules/analyzers/integrity_checker_analyzer.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from database import SessionLocal, ModuleData
from .base_analyzer import BaseAnalyzer

class IntegrityCheckerAnalyzer(BaseAnalyzer):
    """
    Analizador para el módulo integrity_checker.
    Detecta anomalías en cambios de integridad de archivos.
    Características por minuto:
        - total_changes: número total de cambios (modificados + eliminados)
        - modified: archivos modificados
        - deleted: archivos eliminados
    """

    def _collect_data(self) -> list:
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(days=self.window_days)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'integrity_checker',
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
            change_type = d.get('type')  # 'modified' o 'deleted'
            if change_type:
                rows.append({
                    'timestamp': e.timestamp,
                    'type': change_type
                })

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df['interval'] = df['timestamp'].dt.floor('min')
        grouped = df.groupby('interval')

        total_changes = grouped.size().rename('total_changes')
        modified = grouped['type'].apply(lambda x: (x == 'modified').sum()).rename('modified')
        deleted = grouped['type'].apply(lambda x: (x == 'deleted').sum()).rename('deleted')

        features = pd.concat([
            total_changes,
            modified,
            deleted
        ], axis=1).fillna(0)

        return features

    def _train_model(self, features):
        model = IsolationForest(
            contamination=self.config.get('contamination', 0.01),
            random_state=42
        )
        model.fit(features)
        return model, features.columns.tolist()

    def _detect_anomalies(self):
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(seconds=self.detection_interval)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'integrity_checker',
                ModuleData.timestamp >= since
            ).all()
            if len(data) < 5:
                return []
            df = self._extract_features(data)
            if df.empty:
                return []
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
                        'module': 'integrity_checker',
                        'timestamp': interval.isoformat() if hasattr(interval, 'isoformat') else str(interval),
                        'features': row.to_dict()
                    })
            return anomalies
        finally:
            db.close()