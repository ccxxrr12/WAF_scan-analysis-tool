# multiclass_models.py
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, LSTM, Bidirectional, Embedding
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

class LightweightMulticlassModels:
    def __init__(self, n_classes=5):
        self.n_classes = n_classes
        self.models = {}
        self.best_params = {}
        
    def logistic_regression_tunable(self, X_train, y_train, X_val, y_val):
        """可调参的逻辑回归模型"""
        param_grid = {
            'C': [0.1, 1.0, 10.0, 100.0],
            'penalty': ['l1', 'l2', 'elasticnet'],
            'solver': ['liblinear', 'saga'],
            'max_iter': [1000, 2000]
        }
        
        lr = LogisticRegression(multi_class='multinomial', random_state=42)
        
        # 使用网格搜索
        grid_search = GridSearchCV(
            lr, param_grid, cv=3, scoring='accuracy', 
            n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        self.models['logistic_regression'] = grid_search.best_estimator_
        self.best_params['logistic_regression'] = grid_search.best_params_
        
        # 验证集评估
        val_score = grid_search.score(X_val, y_val)
        print(f"逻辑回归最佳参数: {grid_search.best_params_}")
        print(f"逻辑回归验证集准确率: {val_score:.4f}")
        
        return grid_search.best_estimator_
    
    def random_forest_tunable(self, X_train, y_train, X_val, y_val):
        """可调参的随机森林模型"""
        param_dist = {
            'n_estimators': [50, 100, 200],
            'max_depth': [10, 20, 30, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'max_features': ['sqrt', 'log2'],
            'bootstrap': [True, False]
        }
        
        rf = RandomForestClassifier(random_state=42, n_jobs=-1)
        
        # 使用随机搜索（更快）
        random_search = RandomizedSearchCV(
            rf, param_dist, n_iter=20, cv=3, 
            scoring='accuracy', n_jobs=-1, random_state=42, verbose=1
        )
        
        random_search.fit(X_train, y_train)
        
        self.models['random_forest'] = random_search.best_estimator_
        self.best_params['random_forest'] = random_search.best_params_
        
        val_score = random_search.score(X_val, y_val)
        print(f"随机森林最佳参数: {random_search.best_params_}")
        print(f"随机森林验证集准确率: {val_score:.4f}")
        
        return random_search.best_estimator_
    
    def xgboost_tunable(self, X_train, y_train, X_val, y_val):
        """可调参的XGBoost模型"""
        param_grid = {
            'n_estimators': [50, 100, 200],
            'max_depth': [3, 6, 9],
            'learning_rate': [0.01, 0.1, 0.2],
            'subsample': [0.8, 0.9, 1.0],
            'colsample_bytree': [0.8, 0.9, 1.0],
            'reg_alpha': [0, 0.1, 1],
            'reg_lambda': [1, 1.5, 2]
        }
        
        xgb_model = xgb.XGBClassifier(
            objective='multi:softprob',
            random_state=42,
            n_jobs=-1,
            eval_metric='mlogloss'
        )
        
        grid_search = GridSearchCV(
            xgb_model, param_grid, cv=3, 
            scoring='accuracy', n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        self.models['xgboost'] = grid_search.best_estimator_
        self.best_params['xgboost'] = grid_search.best_params_
        
        val_score = grid_search.score(X_val, y_val)
        print(f"XGBoost最佳参数: {grid_search.best_params_}")
        print(f"XGBoost验证集准确率: {val_score:.4f}")
        
        return grid_search.best_estimator_
    
    def build_bilstm_model(self, vocab_size=5000, embedding_dim=100, 
                          max_len=50, lstm_units=64, dropout_rate=0.3):
        """构建轻量级BiLSTM模型"""
        model = Sequential([
            Embedding(vocab_size, embedding_dim, input_length=max_len),
            Bidirectional(LSTM(lstm_units, return_sequences=False)),
            Dropout(dropout_rate),
            Dense(32, activation='relu'),
            Dropout(dropout_rate/2),
            Dense(self.n_classes, activation='softmax')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def bilstm_tunable(self, X_train, y_train, X_val, y_val, 
                       vocab_size=5000, max_len=50):
        """可调参的BiLSTM模型训练"""
        # 定义超参数搜索空间
        param_combinations = [
            {'embedding_dim': 50, 'lstm_units': 32, 'dropout_rate': 0.2, 'batch_size': 32},
            {'embedding_dim': 100, 'lstm_units': 64, 'dropout_rate': 0.3, 'batch_size': 32},
            {'embedding_dim': 100, 'lstm_units': 64, 'dropout_rate': 0.4, 'batch_size': 64},
        ]
        
        best_val_acc = 0
        best_model = None
        best_params = None
        
        for params in param_combinations:
            print(f"\n训练BiLSTM参数组合: {params}")
            
            model = self.build_bilstm_model(
                vocab_size=vocab_size,
                embedding_dim=params['embedding_dim'],
                max_len=max_len,
                lstm_units=params['lstm_units'],
                dropout_rate=params['dropout_rate']
            )
            
            # 回调函数
            callbacks = [
                EarlyStopping(patience=5, restore_best_weights=True),
                ReduceLROnPlateau(factor=0.5, patience=3)
            ]
            
            # 训练模型
            history = model.fit(
                X_train, y_train,
                batch_size=params['batch_size'],
                epochs=30,
                validation_data=(X_val, y_val),
                callbacks=callbacks,
                verbose=0
            )
            
            # 评估验证集
            val_loss, val_acc = model.evaluate(X_val, y_val, verbose=0)
            print(f"验证集准确率: {val_acc:.4f}")
            
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                best_model = model
                best_params = params
        
        self.models['bilstm'] = best_model
        self.best_params['bilstm'] = best_params
        
        print(f"BiLSTM最佳参数: {best_params}")
        print(f"BiLSTM最佳验证集准确率: {best_val_acc:.4f}")
        
        return best_model
    
    def train_all_models(self, X_train_tab, X_train_txt, y_train, 
                        X_val_tab, X_val_txt, y_val, vocab_size=5000, max_len=50):
        """训练所有模型"""
        print("开始训练逻辑回归...")
        self.logistic_regression_tunable(X_train_tab, y_train, X_val_tab, y_val)
        
        print("\n开始训练随机森林...")
        self.random_forest_tunable(X_train_tab, y_train, X_val_tab, y_val)
        
        print("\n开始训练XGBoost...")
        self.xgboost_tunable(X_train_tab, y_train, X_val_tab, y_val)
        
        print("\n开始训练BiLSTM...")
        self.bilstm_tunable(X_train_txt, y_train, X_val_txt, y_val, 
                           vocab_size=vocab_size, max_len=max_len)
    
    def evaluate_models(self, X_test_tab, X_test_txt, y_test):
        """评估所有模型"""
        results = {}
        
        # 评估表格模型
        for name, model in self.models.items():
            if name != 'bilstm':
                y_pred = model.predict(X_test_tab)
                accuracy = accuracy_score(y_test, y_pred)
                
                results[name] = {
                    'accuracy': accuracy,
                    'predictions': y_pred,
                    'model': model
                }
                
                print(f"\n{name} 测试集准确率: {accuracy:.4f}")
                print(f"{name} 分类报告:")
                print(classification_report(y_test, y_pred))
        
        # 评估BiLSTM
        if 'bilstm' in self.models:
            bilstm_model = self.models['bilstm']
            test_loss, test_accuracy = bilstm_model.evaluate(X_test_txt, y_test, verbose=0)
            y_pred_bilstm = np.argmax(bilstm_model.predict(X_test_txt), axis=1)
            
            results['bilstm'] = {
                'accuracy': test_accuracy,
                'predictions': y_pred_bilstm,
                'model': bilstm_model
            }
            
            print(f"\nBiLSTM 测试集准确率: {test_accuracy:.4f}")
            print("BiLSTM 分类报告:")
            print(classification_report(y_test, y_pred_bilstm))
        
        return results
    
    def plot_comparison(self, results, y_test):
        """绘制模型比较图"""
        model_names = list(results.keys())
        accuracies = [results[name]['accuracy'] for name in model_names]
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(model_names, accuracies, color=['skyblue', 'lightgreen', 'lightcoral', 'gold'])
        plt.title('模型性能比较', fontsize=14)
        plt.ylabel('准确率', fontsize=12)
        plt.ylim(0, 1)
        
        # 在柱状图上显示数值
        for bar, accuracy in zip(bars, accuracies):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                    f'{accuracy:.4f}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('models/model_comparison.png', dpi=300, bbox_inches='tight')
        plt.show()
    
    def save_models(self):
        """保存训练好的模型"""
        for name, model in self.models.items():
            if name == 'bilstm':
                model.save(f'models/{name}_waf_model.h5')
            else:
                joblib.dump(model, f'models/{name}_waf_model.pkl')
        
        # 保存最佳参数
        with open('models/best_parameters.json', 'w') as f:
            import json
            # 转换numpy类型为Python原生类型
            serializable_params = {}
            for model_name, params in self.best_params.items():
                if model_name == 'bilstm':
                    serializable_params[model_name] = params
                else:
                    serializable_params[model_name] = {
                        k: (int(v) if isinstance(v, (np.integer, np.int64)) else 
                            float(v) if isinstance(v, (np.floating, np.float64)) else v)
                        for k, v in params.items()
                    }
            json.dump(serializable_params, f, indent=2)
        
        print("所有模型和参数保存完成！")

# 使用示例
if __name__ == "__main__":
    # 加载数据
    data = np.load('data/waf_multiclass_data.npz')
    
    X_train_tab = data['X_train_tab']
    X_val_tab = data['X_val_tab']
    X_test_tab = data['X_test_tab']
    X_train_txt = data['X_train_txt']
    X_val_txt = data['X_val_txt']
    X_test_txt = data['X_test_txt']
    y_train = data['y_train']
    y_val = data['y_val']
    y_test = data['y_test']
    
    print(f"数据形状: 训练集{ X_train_tab.shape}, 验证集{X_val_tab.shape}, 测试集{X_test_tab.shape}")
    
    # 初始化模型训练器
    model_trainer = LightweightMulticlassModels(n_classes=5)
    
    # 训练所有模型
    model_trainer.train_all_models(
        X_train_tab, X_train_txt, y_train,
        X_val_tab, X_val_txt, y_val,
        vocab_size=5000, max_len=50
    )
    
    # 评估模型
    results = model_trainer.evaluate_models(X_test_tab, X_test_txt, y_test)
    
    # 绘制比较图
    model_trainer.plot_comparison(results, y_test)
    
    # 保存模型
    model_trainer.save_models()