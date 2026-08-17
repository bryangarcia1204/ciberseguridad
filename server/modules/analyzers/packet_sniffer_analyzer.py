# modules/analyzers/packet_sniffer_analyzer.py
import pandas as pd
import numpy as np
import re
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from database import SessionLocal, ModuleData  # Importamos ModuleData
from .base_analyzer import BaseAnalyzer

class PacketSnifferAnalyzer(BaseAnalyzer):
    """
    Analizador para el módulo packet_sniffer.
    Extrae información de los logs de texto o de logs JSON estructurados.
    """

    def _collect_data(self) -> list:
        db = SessionLocal()
        try:
            since = datetime.utcnow() - timedelta(days=self.window_days)
            data = db.query(ModuleData).filter(
                ModuleData.module == 'packet_sniffer',
                ModuleData.timestamp >= since
            ).order_by(ModuleData.timestamp).all()
            return data
        finally:
            db.close()

    def _parse_log_message(self, message):
        """Intenta extraer src_ip, dst_ip, proto de un mensaje de log antiguo."""
        # Formato: "IP 192.168.1.1 -> 192.168.1.2 proto:6"
        match = re.search(r'IP (\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+) proto:(\d+)', message)
        if match:
            return {
                'src_ip': match.group(1),
                'dst_ip': match.group(2),
                'protocol': int(match.group(3)),
                'size': 0  # No tenemos tamaño en logs antiguos
            }
        return None

    def _extract_features(self, events):
        if not events:
            return pd.DataFrame()
        rows = []
        for e in events:
            d = e.data
            rows.append({
                'timestamp': e.timestamp,
                'src_ip': d.get('src_ip'),
                'dst_ip': d.get('dst_ip'),
                'protocol': d.get('protocol'),
                'size': d.get('size', 0)
            })

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df['hour'] = df['timestamp'].dt.floor('h')
        grouped = df.groupby('hour')

        # Características base
        total_packets = grouped.size().rename('total_packets')
        unique_src_ips = grouped['src_ip'].nunique().rename('unique_src_ips')
        unique_dst_ips = grouped['dst_ip'].nunique().rename('unique_dst_ips')

        # Conteo por protocolo
        protocol_counts = grouped['protocol'].value_counts().unstack(fill_value=0)
        protocol_counts.columns = [f'protocol_{int(col)}' for col in protocol_counts.columns]

        # Tamaño medio
        if df['size'].sum() > 0:
            avg_packet_size = grouped['size'].mean().rename('avg_packet_size')
        else:
            avg_packet_size = pd.Series(0, index=grouped.indices).rename('avg_packet_size')

        # Hora del día
        hour_of_day = grouped['hour'].first().dt.hour
        hour_sin = np.sin(2 * np.pi * hour_of_day / 24).rename('hour_sin')
        hour_cos = np.cos(2 * np.pi * hour_of_day / 24).rename('hour_cos')

        features = pd.concat([
            total_packets,
            unique_src_ips,
            unique_dst_ips,
            avg_packet_size,
            protocol_counts,
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
            # Cambiamos Event por ModuleData
            data = db.query(ModuleData).filter(
                ModuleData.module == 'packet_sniffer',
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
                    hour = index
                    anomalies.append({
                        'module': 'packet_sniffer',
                        'timestamp': hour.isoformat() if hasattr(hour, 'isoformat') else str(hour),
                        'features': row.to_dict()
                    })
            return anomalies
        finally:
            db.close()