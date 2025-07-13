package org.sonarsource.plugins.trivy;

import lombok.Getter;
import lombok.Setter;
import org.sonarsource.plugins.trivy.model.TrivyData;

import java.util.ArrayList;
import java.util.List;

/**
 * Data store for caching Trivy data across Sensors
 */
@Getter
@Setter
public class TrivyDataStore {

    private static final TrivyDataStore INSTANCE = new TrivyDataStore();

    public static TrivyDataStore instance(){
        return INSTANCE;
    }

    private List<TrivyData> trivyData = new ArrayList<>();

    private TrivyDataStore() {
        // Private constructor for singleton pattern
    }

    public void addTrivyData(TrivyData data) {
        this.trivyData.add(data);
    }
} 