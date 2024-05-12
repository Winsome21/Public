from flask import Flask, request, jsonify
import numpy as np
import math
import pickle
from collections import Counter

app = Flask(__name__)

model_data = pickle.load(open('dga_model_data.pkl', 'rb'))
clf = model_data['clf']
umbrella_vc = model_data['umbrella_vc']
dict_vc = model_data['dict_vc']
umbrella_counts = model_data['umbrella_counts']
dict_counts = model_data['dict_counts']

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def test_it(domain, clf):
    _umbrella_match = umbrella_counts * umbrella_vc.transform([domain]).T
    _dict_match = dict_counts * dict_vc.transform([domain]).T
    _X = np.array([len(domain), entropy(domain), _umbrella_match, _dict_match], dtype=object).reshape(1, -1)
    prediction = clf.predict(_X)[0]
    return prediction

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    domain = data.get('domain')
    if not domain:
        return jsonify({'error': 'Missing domain'}), 400
    
    prediction = test_it(domain, clf)
    return jsonify({'domain': domain, 'prediction': prediction})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)