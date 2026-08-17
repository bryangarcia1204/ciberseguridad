# modules/analyzers/waf_analyzer.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from database import SessionLocal, ModuleData  # Importamos ModuleData
from .base_analyzer import BaseAnalyzer

class WafAnalyzer(BaseAnalyzer):
    """
    Analizador para el módulo waf_module.
    Detecta anomalías en los bloqueos del WAF basándose en:
    - Número de bloqueos por hora
    - Hora del día (ciclicidad)
    """

    def _collect_data(self) -> list:
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(days=self.window_days)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'waf_module',
                ModuleData.timestamp >= since
            ).order_by(ModuleData.timestamp).all()
            return data
        finally:
            db.close()

    def _extract_features(self, events):
        """
        Convierte la lista de ModuleData en un DataFrame con características por hora.
        Se espera que cada registro tenga en data el campo 'blocked' (bool) o similar.
        """
        if not events:
            return pd.DataFrame()

        rows = []
        for e in events:
            d = e.data
            # El módulo waf_module guarda datos con 'blocked' True/False
            rows.append({
                'timestamp': e.timestamp,
                'blocked': d.get('blocked', False)
            })

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df['hour'] = df['timestamp'].dt.floor('h')
        grouped = df.groupby('hour')

        total_blocks = grouped['blocked'].sum().rename('total_blocks')

        hour_of_day = grouped['hour'].first().dt.hour
        hour_sin = np.sin(2 * np.pi * hour_of_day / 24).rename('hour_sin')
        hour_cos = np.cos(2 * np.pi * hour_of_day / 24).rename('hour_cos')

        features = pd.concat([
            total_blocks,
            hour_sin,
            hour_cos
        ], axis=1).fillna(0)

        return features

    def _train_model(self, features):
        model = IsolationForest(contamination=0.01, random_state=42)
        model.fit(features)
        return model, features.columns.tolist()

    def _detect_anomalies(self):
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(seconds=self.detection_interval)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'waf_module',
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
                    hour = index
                    anomalies.append({
                        'module': 'waf_module',
                        'timestamp': hour.isoformat() if hasattr(hour, 'isoformat') else str(hour),
                        'features': row.to_dict()
                    })
            return anomalies
        finally:
            db.close()