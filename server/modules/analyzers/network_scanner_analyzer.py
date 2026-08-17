# modules/analyzers/network_scanner_analyzer.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from database import SessionLocal, ModuleData  # Importamos ModuleData
from .base_analyzer import BaseAnalyzer

class NetworkScannerAnalyzer(BaseAnalyzer):
    """
    Analizador para el módulo network_scanner.
    Detecta anomalías en la detección de dispositivos en la red.
    Características por hora:
        - total_devices: número de dispositivos detectados
        - new_devices: número de nuevos dispositivos (alertas new_device)
        - unique_ips: IPs distintas
        - hour_sin, hour_cos
    """

    def _collect_data(self) -> list:
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(days=self.window_days)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'network_scanner',
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
            # El módulo network_scanner guarda datos con ip, mac, new (bool)
            rows.append({
                'timestamp': e.timestamp,
                'ip': d.get('ip'),
                'new': d.get('new', False)
            })

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df['hour'] = df['timestamp'].dt.floor('h')
        grouped = df.groupby('hour')

        total_devices = grouped.size().rename('total_devices')
        new_devices = grouped['new'].sum().rename('new_devices')
        unique_ips = grouped['ip'].nunique().rename('unique_ips')

        hour_of_day = grouped['hour'].first().dt.hour
        hour_sin = np.sin(2 * np.pi * hour_of_day / 24).rename('hour_sin')
        hour_cos = np.cos(2 * np.pi * hour_of_day / 24).rename('hour_cos')

        features = pd.concat([
            total_devices,
            new_devices,
            unique_ips,
            hour_sin,
            hour_cos
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
                ModuleData.module == 'network_scanner',
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
            for pred, (idx, row) in zip(preds, df.iterrows()):
                if pred == -1:
                    anomalies.append({
                        'module': 'network_scanner',
                        'timestamp': idx.isoformat() if hasattr(idx, 'isoformat') else str(idx),
                        'features': row.to_dict()
                    })
            return anomalies
        finally:
            db.close()