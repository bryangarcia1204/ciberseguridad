# modules/analyzers/log_monitor_analyzer.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from database import SessionLocal, ModuleData
from .base_analyzer import BaseAnalyzer

class LogMonitorAnalyzer(BaseAnalyzer):
    """
    Analizador para el módulo log_monitor.
    Detecta anomalías en los logs de acceso web o firewall.
    Características por minuto:
        - total_requests: número total de eventos
        - unique_ips: número de IPs distintas
        - avg_requests_per_ip: promedio de peticiones por IP
    """

    def _collect_data(self) -> list:
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(days=self.window_days)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'log_monitor',
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
            ip = e.data.get('ip')
            rows.append({
                'timestamp': e.timestamp,
                'ip': ip,
            })

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df['interval'] = df['timestamp'].dt.floor('min')
        grouped = df.groupby('interval')

        total_requests = grouped.size().rename('total_requests')
        unique_ips = grouped['ip'].nunique().rename('unique_ips')
        avg_requests_per_ip = (total_requests / (unique_ips + 1e-5)).rename('avg_requests_per_ip')

        features = pd.concat([
            total_requests,
            unique_ips,
            avg_requests_per_ip
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
                ModuleData.module == 'log_monitor',
                ModuleData.timestamp >= since
            ).all()
            if len(data) < 10:
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
                        'module': 'log_monitor',
                        'timestamp': interval.isoformat() if hasattr(interval, 'isoformat') else str(interval),
                        'features': row.to_dict()
                    })
            return anomalies
        finally:
            db.close()